import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from sources import get_scrapers
from console import IPLookupConsole
from utils import CursorManager

class IPLookup:
    def __init__(self):
        self.console = IPLookupConsole()
        self.cursor_manager = CursorManager()
        self.completed = 0

    def _fetch_from_source(self, source, ip):
        try:
            return source.fetch(ip)
        except Exception as e:
            self.console.print_error(f"Error fetching from {source.name} for {ip}: {str(e)}")
            return set()

    def _save_domains(self, domains, output_file):
        if domains:
            with open(output_file, "a", encoding="utf-8") as f:
                f.write("\n".join(sorted(domains)) + "\n")

    def process_ip(self, ip, output_file, scrapers, total):
        self.console.print_ip_start(ip)
        self.console.print_progress(self.completed, total)

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(self._fetch_from_source, source, ip) for source in scrapers]
            results = [f.result() for f in as_completed(futures)]

        domains = set().union(*results) if results else set()

        self.console.update_ip_stats(ip, len(domains))
        self.console.print_ip_complete(ip, len(domains))
        self._save_domains(domains, output_file)

        self.completed += 1
        self.console.print_progress(self.completed, total)
        return domains

    def run(self, ips, output_file):
        if not ips:
            raise ValueError("No valid IPs provided")
        
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        self.completed = 0
        all_domains = set()
        total = len(ips)
        scrapers = get_scrapers()
        
        with self.cursor_manager:
            batch_size = 1000
            for i in range(0, len(ips), batch_size):
                batch_ips = ips[i:i + batch_size]
                with ThreadPoolExecutor(max_workers=5) as executor:
                    futures = [
                        executor.submit(self.process_ip, ip, output_file, scrapers, total)
                        for ip in batch_ips
                    ]
                    for future in as_completed(futures):
                        try:
                            all_domains.update(future.result())
                        except Exception as e:
                            self.console.print_error(f"Error processing IP: {str(e)}")
        
        self.console.print_final_summary(output_file)
        return all_domains