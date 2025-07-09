import os
import re
import json
import time
import random
import requests
import datetime
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from rich.console import Console
import telegram
from telegram.ext import Application
import asyncio
import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
BOT_TOKEN = "7687952078:AAErW9hkz0p47xGPocEBMSj58PTEDrwyWOk"
DOMAINS_CHAT_ID = -1002818240346
SUBDOMAINS_CHAT_ID = -4827615311
HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
]
RENDER_WEBHOOK = os.getenv("RENDER_WEBHOOK_URL", "")  # Set this in Render environment variables

# Console for logging
class SubFinderConsole(Console):
    def __init__(self):
        super().__init__()
        self.total_subdomains = 0
        self.domain_stats = {}

    def print_domain_start(self, domain):
        self.print(f"[cyan]Processing: {domain}[/cyan]")
        logger.info(f"Processing domain: {domain}")

    def update_domain_stats(self, domain, count):
        self.domain_stats[domain] = count
        self.total_subdomains += count

    def print_domain_complete(self, domain, count):
        self.print(f"[green]{domain}: {count} subdomains found[/green]")
        logger.info(f"Completed {domain}: {count} subdomains found")

    def print_final_summary(self, output_file):
        print("\r\033[K", end="")
        self.print(f"\n[green]Total: [bold]{self.total_subdomains}[/bold] subdomains found")
        self.print(f"[green]Results saved to {output_file}[/green]")
        logger.info(f"Total: {self.total_subdomains} subdomains found, saved to {output_file}")

    def print_progress(self, current, total):
        self.print(f"Progress: {current} / {total}", end="\r")
        logger.info(f"Progress: {current}/{total}")

    def print_error(self, message):
        self.print(f"[red]{message}[/red]")
        logger.error(message)

# Request Handler
class RequestHandler:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    def _get_headers(self):
        headers = HEADERS.copy()
        headers["user-agent"] = random.choice(USER_AGENTS)
        return headers

    def get(self, url, timeout=10):
        for attempt in range(3):
            try:
                response = self.session.get(url, timeout=timeout, headers=self._get_headers())
                if response.status_code == 200:
                    return response
                logger.warning(f"Request to {url} failed with status {response.status_code}, attempt {attempt + 1}")
            except requests.RequestException as e:
                logger.error(f"Request to {url} failed: {e}, attempt {attempt + 1}")
            time.sleep(2 ** attempt)  # Exponential backoff
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

# Domain Validator
class DomainValidator:
    DOMAIN_REGEX = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$'
    )

    @classmethod
    def is_valid_domain(cls, domain):
        return bool(
            domain
            and isinstance(domain, str)
            and cls.DOMAIN_REGEX.match(domain)
        )

    @staticmethod
    def filter_valid_subdomains(subdomains, domain):
        if not domain or not isinstance(domain, str):
            return set()
        domain_suffix = f".{domain}"
        result = set()
        for sub in subdomains:
            if not isinstance(sub, str):
                continue
            if sub == domain or sub.endswith(domain_suffix):
                result.add(sub)
        return result

# Cursor Manager
class CursorManager:
    def __enter__(self):
        print('\033[?25l', end='', flush=True)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        print('\033[?25h', end='', flush=True)

# Subdomain Sources
class SubdomainSource(RequestHandler, ABC):
    def __init__(self, name):
        super().__init__()
        self.name = name

    @abstractmethod
    def fetch(self, domain):
        pass

class CrtshSource(SubdomainSource):
    def __init__(self):
        super().__init__("Crt.sh")

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if response and response.headers.get('Content-Type') == 'application/json':
            for entry in response.json():
                subdomains.update(entry['name_value'].splitlines())
        return subdomains

class HackertargetSource(SubdomainSource):
    def __init__(self):
        super().__init__("Hackertarget")

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if response and 'text' in response.headers.get('Content-Type', ''):
            subdomains.update([line.split(",")[0] for line in response.text.splitlines()])
        return subdomains

class RapidDnsSource(SubdomainSource):
    def __init__(self):
        super().__init__("RapidDNS")

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://rapiddns.io/subdomain/{domain}?full=1")
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('td'):
                text = link.get_text(strip=True)
                if text.endswith(f".{domain}"):
                    subdomains.add(text)
        return subdomains

class AnubisDbSource(SubdomainSource):
    def __init__(self):
        super().__init__("AnubisDB")

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://jldc.me/anubis/subdomains/{domain}")
        if response:
            subdomains.update(response.json())
        return subdomains

class AlienVaultSource(SubdomainSource):
    def __init__(self):
        super().__init__("AlienVault")

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
        if response:
            for entry in response.json().get("passive_dns", []):
                hostname = entry.get("hostname")
                if hostname:
                    subdomains.add(hostname)
        return subdomains

class CertSpotterSource(SubdomainSource):
    def __init__(self):
        super().__init__("CertSpotter")

    def fetch(self, domain):
        subdomains = set()
        response = self.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names")
        if response:
            for cert in response.json():
                subdomains.update(cert.get('dns_names', []))
        return subdomains

def get_sources():
    return [
        CrtshSource(),
        HackertargetSource(),
        RapidDnsSource(),
        AnubisDbSource(),
        AlienVaultSource(),
        CertSpotterSource(),
    ]

# SubFinder
class SubFinder:
    def __init__(self, bot):
        self.console = SubFinderConsole()
        self.completed = 0
        self.cursor_manager = CursorManager()
        self.bot = bot

    def _fetch_from_source(self, source, domain):
        try:
            found = source.fetch(domain)
            return DomainValidator.filter_valid_subdomains(found, domain)
        except Exception as e:
            logger.error(f"Error fetching from {source.name} for {domain}: {e}")
            return set()

    @staticmethod
    def save_subdomains(subdomains, output_file):
        if subdomains:
            os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(subdomains)) + "\n")
            logger.info(f"Saved subdomains to {output_file}")

    async def upload_to_telegram(self, output_file, chat_id):
        try:
            with open(output_file, 'rb') as f:
                await self.bot.send_document(chat_id=chat_id, document=f, caption=f"Subdomains for {os.path.basename(output_file)}")
            logger.info(f"Uploaded {output_file} to Telegram chat {chat_id}")
        except Exception as e:
            logger.error(f"Failed to upload {output_file} to Telegram: {e}")

    def process_domain(self, domain, output_file, sources, total):
        if not DomainValidator.is_valid_domain(domain):
            self.completed += 1
            logger.warning(f"Invalid domain: {domain}")
            return set()

        self.console.print_domain_start(domain)
        self.console.print_progress(self.completed, total)

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(self._fetch_from_source, source, domain) for source in sources]
            results = [f.result() for f in as_completed(futures)]

        subdomains = set().union(*results) if results else set()
        self.console.update_domain_stats(domain, len(subdomains))
        self.console.print_domain_complete(domain, len(subdomains))
        self.save_subdomains(subdomains, output_file)

        self.completed += 1
        self.console.print_progress(self.completed, total)
        return subdomains

    async def process_file(self, file_path, output_file, sources):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                domains = [d.strip() for d in f if DomainValidator.is_valid_domain(d.strip())]
            if not domains:
                self.console.print_error(f"No valid domains in {file_path}")
                return

            self.completed = 0
            all_subdomains = set()
            total = len(domains)

            with self.cursor_manager:
                with ThreadPoolExecutor(max_workers=3) as executor:
                    futures = [
                        executor.submit(self.process_domain, domain, f"temp_{domain}.txt", sources, total)
                        for domain in domains
                    ]
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            all_subdomains.update(result)
                        except Exception as e:
                            self.console.print_error(f"Error processing domain: {str(e)}")

            self.save_subdomains(all_subdomains, output_file)
            await self.upload_to_telegram(output_file, SUBDOMAINS_CHAT_ID)
            self.console.print_final_summary(output_file)
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")

# Telegram Handler
class TelegramHandler:
    def __init__(self):
        self.bot = telegram.Bot(token=BOT_TOKEN)
        self.current_file_index = 1
        self.max_files = 65

    async def fetch_file(self, chat_id, file_index):
        try:
            async with Application.builder().token(BOT_TOKEN).build() as app:
                messages = await self.bot.get_chat_history(chat_id=chat_id, limit=100)
                for message in messages:
                    if message.document and message.document.file_name == f"domain_part_{file_index}.txt":
                        file = await message.document.get_file()
                        file_path = f"domain_part_{file_index}.txt"
                        await file.download_to_drive(file_path)
                        logger.info(f"Downloaded {file_path} from Telegram")
                        return file_path
                logger.warning(f"File domain_part_{file_index}.txt not found in chat {chat_id}")
                return None
        except Exception as e:
            logger.error(f"Error fetching file {file_index}: {e}")
            return None

    async def process_files(self):
        while self.current_file_index <= self.max_files:
            file_path = await self.fetch_file(DOMAINS_CHAT_ID, self.current_file_index)
            if not file_path:
                logger.warning(f"Skipping file {self.current_file_index}, not found")
                self.current_file_index += 1
                continue

            output_file = f"domain_part_{self.current_file_index}_output.txt"
            subfinder = SubFinder(self.bot)
            await subfinder.process_file(file_path, output_file, get_sources())

            # Clean up
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"Deleted {file_path}")
                if os.path.exists(output_file):
                    os.remove(output_file)
                    logger.info(f"Deleted {output_file}")
            except Exception as e:
                logger.error(f"Error cleaning up files: {e}")

            # Restart Render instance
            try:
                if RENDER_WEBHOOK:
                    requests.post(RENDER_WEBHOOK)
                    logger.info("Triggered Render restart via webhook")
                else:
                    subprocess.run(["systemctl", "reboot"], check=False)
                    logger.info("Initiated system reboot")
            except Exception as e:
                logger.error(f"Error restarting Render: {e}")

            self.current_file_index += 1
            time.sleep(10)  # Delay to ensure cleanup and restart

async def main():
    telegram_handler = TelegramHandler()
    await telegram_handler.process_files()

if __name__ == "__main__":
    asyncio.run(main())