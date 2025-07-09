import os
import sys
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from abc import ABC, abstractmethod
from bs4 import BeautifulSoup
import re
import random
import requests.packages.urllib3

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = "7687952078:AAErW9hkz0p47xGPocEBMSj58PTEDrwyWOk"
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")  # Set in Render environment variables
STATE_FILE = "processed_files.json"

# HTTP Headers and User Agents
HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
]

# SubFinderConsole
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
        self.print(f"\n[green]Total: [bold]{self.total_subdomains}[/bold] subdomains found")
        self.print(f"[green]Results saved to {output_file}[/green]")

    def print_progress(self, current, total):
        self.print(f"Progress: {current} / {total}", end="\r")
    
    def print_error(self, message):
        self.print(f"[red]{message}[/red]")

# RequestHandler
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

# DomainValidator
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

# CursorManager
class CursorManager:
    def __enter__(self):
        print('\033[?25l', end='', flush=True)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        print('\033[?25h', end='', flush=True)

# SubdomainSource
class SubdomainSource(RequestHandler, ABC):
    def __init__(self, name):
        super().__init__()
        self.name = name

    @abstractmethod
    def fetch(self, domain):
        pass

# Source Implementations
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
    def __init__(self):
        self.console = SubFinderConsole()
        self.completed = 0
        self.cursor_manager = CursorManager()

    def _fetch_from_source(self, source, domain):
        try:
            found = source.fetch(domain)
            return DomainValidator.filter_valid_subdomains(found, domain)
        except Exception:
            return set()

    @staticmethod
    def save_subdomains(subdomains, output_file):
        if subdomains:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(subdomains)) + "\n")

    def process_domain(self, domain, output_file, sources, total):
        if not DomainValidator.is_valid_domain(domain):
            self.completed += 1
            return set()

        self.console.print_domain_start(domain)
        self.console.print_progress(self.completed, total)
        
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [
                executor.submit(self._fetch_from_source, source, domain)
                for source in sources
            ]
            results = [f.result() for f in as_completed(futures)]

        subdomains = set().union(*results) if results else set()

        self.console.update_domain_stats(domain, len(subdomains))
        self.console.print_domain_complete(domain, len(subdomains))
        self.save_subdomains(subdomains, output_file)

        self.completed += 1
        self.console.print_progress(self.completed, total)
        return subdomains

    def run(self, domains, output_file, sources):
        if not domains:
            self.console.print_error("No valid domains provided")
            return set()

        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        self.completed = 0
        all_subdomains = set()
        total = len(domains)

        with self.cursor_manager:
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(self.process_domain, domain, output_file, sources, total)
                    for domain in domains
                ]
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        all_subdomains.update(result)
                    except Exception as e:
                        self.console.print(f"Error processing domain: {str(e)}")

            self.console.print_final_summary(output_file)
            return all_subdomains

# Telegram Functions
def send_file_to_telegram(file_path, chat_id):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    with open(file_path, 'rb') as f:
        files = {'document': f}
        data = {'chat_id': chat_id}
        response = requests.post(url, files=files, data=data)
        return response.status_code == 200

# State Management
def load_processed_files():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return []

def save_processed_file(file_name):
    processed = load_processed_files()
    processed.append(file_name)
    with open(STATE_FILE, 'w') as f:
        json.dump(processed, f)

def get_next_file():
    processed = load_processed_files()
    for i in range(1, 66):
        file_name = f"domains/domain_part_{i}.txt"
        if file_name not in processed and os.path.exists(file_name):
            return file_name
    return None

# Main Execution
def main():
    if not TELEGRAM_CHAT_ID:
        print("Error: TELEGRAM_CHAT_ID not set in environment variables")
        sys.exit(1)

    next_file = get_next_file()
    if not next_file:
        print("All files processed")
        sys.exit(0)

    # Read domains from file
    with open(next_file, 'r') as f:
        domains = [d.strip() for d in f if DomainValidator.is_valid_domain(d.strip())]

    if not domains:
        print(f"No valid domains in {next_file}")
        save_processed_file(next_file)
        sys.exit(2)  # Trigger restart

    # Generate output file name
    output_file = f"{next_file.replace('.txt', '_output.txt').replace('domains/', '')}"

    # Run SubFinder
    subfinder = SubFinder()
    sources = get_sources()
    subfinder.run(domains, output_file, sources)

    # Send output to Telegram
    if os.path.exists(output_file):
        if send_file_to_telegram(output_file, TELEGRAM_CHAT_ID):
            print(f"Sent {output_file} to Telegram")
            # Clean up output file to save space
            os.remove(output_file)
        else:
            print(f"Failed to send {output_file} to Telegram")
            sys.exit(1)

    # Mark file as processed
    save_processed_file(next_file)

    # Exit with code to trigger restart
    sys.exit(2)

if __name__ == "__main__":
    main()