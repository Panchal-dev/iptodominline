import os
import time
import datetime
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from bugscanx.utils.prompts import get_input
from .logger import SubFinderConsole
from .sources import get_sources
from .utils import DomainValidator, CursorManager
from telegram import Bot
from telegram.error import TelegramError

class SubFinder:
    def __init__(self, bot_token, domains_chat_id, subdomain_chat_id):
        self.console = SubFinderConsole()
        self.completed = 0
        self.cursor_manager = CursorManager()
        self.bot = Bot(token=bot_token)
        self.domains_chat_id = domains_chat_id
        self.subdomain_chat_id = subdomain_chat_id
        self.domains_dir = "domains"
        self.outputs_dir = "outputs"
        os.makedirs(self.domains_dir, exist_ok=True)
        os.makedirs(self.outputs_dir, exist_ok=True)

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

    async def fetch_input_files(self):
        try:
            updates = await self.bot.get_updates(chat_id=self.domains_chat_id, limit=100)
            files_fetched = 0
            for update in updates:
                if update.message and update.message.document:
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

    async def run(self):
        sources = get_sources()
        while True:
            # Fetch input files
            files_fetched = await self.fetch_input_files()
            if files_fetched == 0:
                self.console.print_error("No new domain files found. Sleeping for 10 minutes.")
                time.sleep(600)
                continue

            # Process each file one at a time
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
                        continue

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
                    os.remove(output_file)  # Remove output file after upload

                    # Trigger Render restart by exiting (Render will auto-restart)
                    self.console.print("[yellow]Restarting service to comply with free tier limits[/yellow]")
                    return  # Exit to trigger restart

                except Exception as e:
                    self.console.print_error(f"Error processing {file_name}: {str(e)}")
                    os.remove(input_file)  # Remove file to avoid reprocessing
                    continue

            # If no files left, sleep and check again
            self.console.print("[yellow]No more files to process. Sleeping for 10 minutes.[/yellow]")
            time.sleep(600)

async def main():
    bot_token = "7687952078:AAErW9hkz0p47xGPocEBMSj58PTEDrwyWOk"
    domains_chat_id = -1002818240346
    subdomain_chat_id = -4827615311
    subfinder = SubFinder(bot_token, domains_chat_id, subdomain_chat_id)
    await subfinder.run()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())