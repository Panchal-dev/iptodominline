import os
import time
import datetime
import re
import random
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from abc import ABC, abstractmethod
from bs4 import BeautifulSoup
from rich.console import Console
from telegram import Bot, Update
from telegram.error import TelegramError
import urllib3
from aiohttp import web
import asyncio

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Console
class SubFinderConsole(Console):
    def __init__(self):
        super().__init__()
        self.total_subdomains = 0
        self.domain_stats = {}

    def print_domain_start(self, domain):
        self.print(f"[cyan]Processing: {domain}[/cyan]")
    
    def update_domain_stats(self, domain, count):
        self.domain_stats[domain] = count
        self.total_subdomains += count
    
    def print_domain_complete(self, domain, count):
        self.print(f"[green]{domain}: {count} subdomains found[/green]")
    
    def print_final_summary(self, output_file):
        print("\r\033[K", end="")
        self.print(f"\n[green]Total: [bold]{self.total_subdomains}[/bold] subdomains found")
        self.print(f"[green]Results saved to {output_file}[/green]")

    def print_progress(self, current, total):
        self.print(f"Progress: {current} / {total}", end="\r")
    
    def print_error(self, message):
        self.print(f"[red]{message}[/red]")

# Utils
HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, sdch",
    "Accept-Language": "en-US,en;q=0.8",
}
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36",
]

class RequestHandler:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False

    def _get_headers(self):
        headers = HEADERS.copy()
        headers["user-agent"] = random.choice(USER_AGENTS)
        return headers

    def get(self, url, timeout=10):
        try:
            response = self.session.get(url, timeout=timeout, headers=self._get_headers())
            if response.status_code == 200:
                return response
        except requests.RequestException:
            pass
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

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

class CursorManager:
    def __enter__(self):
        print('\033[?25l', end='', flush=True)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        print('\033[?25h', end='', flush=True)

# Sources
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
            subdomains.update(
                [line.split(",")[0] for line in response.text.splitlines()]
            )
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

class C99Source(SubdomainSource):
    def __init__(self):
        super().__init__("C99")

    def fetch(self, domain):
        subdomains = set()
        dates = [(datetime.datetime.now() - datetime.timedelta(days=i)).strftime('%Y-%m-%d') 
                 for i in range(7)]
        
        for date in dates:
            url = f"https://subdomainfinder.c99.nl/scans/{date}/{domain}"
            response = self.get(url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.select('td a.link.sd'):
                    text = link.get_text(strip=True)
                    if text.endswith(f".{domain}"):
                        subdomains.add(text)
                if subdomains:
                    break
        return subdomains

def get_sources():
    return [
        CrtshSource(),
        HackertargetSource(),
        RapidDnsSource(),
        AnubisDbSource(),
        AlienVaultSource(),
        CertSpotterSource(),
        # C99Source()
    ]

# SubFinder
class SubFinder:
    def __init__(self, bot_token, domains_chat_id, subdomain_chat_id):
        self.console = SubFinderConsole()
        self.completed = 0
        self.cursor_manager = CursorManager()
        self.bot = Bot(token=bot_token)
        self.domains_chat_id = domains_chat_id
        self.subdomain_chat_id = subdomain_chat_id
        self.domains_dir = "/domains"
        self.outputs_dir = "/outputs"
        os.makedirs(self.domains_dir, exist_ok=True)
        os.makedirs(self.outputs_dir, exist_ok=True)
        self.webhook_set = False

    def _fetch_from_source(self, source, domain):
        try:
            found = source.fetch(domain)
            return DomainValidator.filter_valid_subdomains(found, domain)
        except Exception as e:
            self.console.print_error(f"Error in {source.name} for {domain}: {str(e)}")
            return set()

    def save_subdomains(self, subdomains, output_file):
        if subdomains:
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(sorted(subdomains)) + "\n")
                self.console.print(f"[green]Saved {len(subdomains)} subdomains to {output_file}[/green]")
            except Exception as e:
                self.console.print_error(f"Error saving to {output_file}: {str(e)}")

    def process_domain(self, domain, output_file, sources, total):
        if not DomainValidator.is_valid_domain(domain):
            self.console.print_error(f"Invalid domain: {domain}")
            self.completed += 1
            return set()

        self.console.print_domain_start(domain)
        self.console.print_progress(self.completed, total)
        
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [
                executor.submit(self._fetch_from_source, source, domain)
                for source in sources
            ]
            results = []
            for f in as_completed(futures, timeout=300):  # 5-minute timeout per source
                try:
                    results.append(f.result())
                except Exception as e:
                    self.console.print_error(f"Source timeout/error: {str(e)}")

        subdomains = set().union(*results) if results else set()

        self.console.update_domain_stats(domain, len(subdomains))
        self.console.print_domain_complete(domain, len(subdomains))
        self.save_subdomains(subdomains, output_file)

        self.completed += 1
        self.console.print_progress(self.completed, total)
        return subdomains

    async def fetch_input_files(self, update):
        try:
            files_fetched = 0
            if update.message and update.message.document and update.message.chat.id == self.domains_chat_id:
                file_name = update.message.document.file_name
                if file_name.startswith("domain_part_") and file_name.endswith(".txt"):
                    file_id = update.message.document.file_id
                    file_info = await self.bot.get_file(file_id)
                    file_path = os.path.join(self.domains_dir, file_name)
                    file_content = requests.get(file_info.file_path).content
                    with open(file_path, "wb") as f:
                        f.write(file_content)
                    self.console.print(f"[green]Downloaded {file_name}[/green]")
                    files_fetched += 1
            return files_fetched
        except TelegramError as e:
            self.console.print_error(f"Telegram fetch error: {str(e)}")
            return 0

    async def upload_output_file(self, output_file):
        try:
            with open(output_file, "rb") as f:
                await self.bot.send_document(
                    chat_id=self.subdomain_chat_id,
                    document=f,
                    caption=f"Subdomains for {os.path.basename(output_file).replace('_output.txt', '')}"
                )
            self.console.print(f"[green]Uploaded {output_file} to Subdomain group[/green]")
        except TelegramError as e:
            self.console.print_error(f"Telegram upload error: {str(e)}")

    async def process_file(self):
        sources = get_sources()
        for file_name in sorted(os.listdir(self.domains_dir)):
            if not file_name.startswith("domain_part_") or not file_name.endswith(".txt"):
                continue

            input_file = os.path.join(self.domains_dir, file_name)
            output_file = os.path.join(self.outputs_dir, file_name.replace(".txt", "_output.txt"))
            
            try:
                with open(input_file, 'r') as f:
                    domains = [d.strip() for d in f if DomainValidator.is_valid_domain(d.strip())]
                if not domains:
                    self.console.print_error(f"No valid domains in {file_name}")
                    os.remove(input_file)
                    return False

                self.completed = 0
                all_subdomains = set()
                total = len(domains)

                with self.cursor_manager:
                    for domain in domains:
                        subdomains = self.process_domain(domain, output_file, sources, total)
                        all_subdomains.update(subdomains)

                self.console.print_final_summary(output_file)
                await self.upload_output_file(output_file)
                os.remove(input_file)  # Remove input file after processing
                if os.path.exists(output_file):
                    os.remove(output_file)  # Remove output file after upload

                # Trigger Render restart by returning True
                self.console.print("[yellow]Restarting service to comply with free tier limits[/yellow]")
                return True

            except Exception as e:
                self.console.print_error(f"Error processing {file_name}: {str(e)}")
                if os.path.exists(input_file):
                    os.remove(input_file)  # Remove file to avoid reprocessing
                return False

        return False

    async def handle_webhook(self, request):
        try:
            data = await request.json()
            update = Update.de_json(data, self.bot)
            if update:
                files_fetched = await self.fetch_input_files(update)
                if files_fetched > 0:
                    should_restart = await self.process_file()
                    if should_restart:
                        return web.Response(status=200)  # Exit to trigger restart
            return web.Response(status=200)
        except Exception as e:
            self.console.print_error(f"Webhook error: {str(e)}")
            return web.Response(status=500)

    async def setup_webhook(self, webhook_url):
        if not self.webhook_set:
            try:
                await self.bot.set_webhook(url=webhook_url)
                self.console.print(f"[green]Webhook set to {webhook_url}[/green]")
                self.webhook_set = True
            except TelegramError as e:
                self.console.print_error(f"Failed to set webhook: {str(e)}")

async def main():
    bot_token = "7687952078:AAErW9hkz0p47xGPocEBMSj58PTEDrwyWOk"
    domains_chat_id = -1002818240346
    subdomain_chat_id = -4827615311
    subfinder = SubFinder(bot_token, domains_chat_id, subdomain_chat_id)

    # Get Render port (defaults to 10000 for free tier)
    port = int(os.getenv("PORT", 10000))
    
    # Construct webhook URL using RENDER_EXTERNAL_HOSTNAME
    render_hostname = os.getenv("RENDER_EXTERNAL_HOSTNAME")
    if not render_hostname:
        subfinder.console.print_error("RENDER_EXTERNAL_HOSTNAME not set. Cannot set webhook.")
        return
    
    webhook_url = f"https://{render_hostname}/webhook"
    
    # Set up webhook
    await subfinder.setup_webhook(webhook_url)

    # Start web server
    app = web.Application()
    app.router.add_post('/webhook', subfinder.handle_webhook)
    
    # Check for existing files and process them
    should_restart = await subfinder.process_file()
    if should_restart:
        return  # Exit to trigger restart

    # Start the web server
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', port)
    subfinder.console.print(f"[green]Starting web server on port {port}[/green]")
    await site.start()
    
    # Keep the server running
    while True:
        await asyncio.sleep(3600)  # Sleep to keep the event loop alive

if __name__ == "__main__":
    asyncio.run(main())