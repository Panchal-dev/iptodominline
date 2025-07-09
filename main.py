import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pymongo import MongoClient
from dotenv import load_dotenv
from logger import SubFinderConsole
from sources import get_sources
from utils import DomainValidator, CursorManager

class SubFinder:
    def __init__(self):
        self.console = SubFinderConsole()
        self.completed = 0
        self.cursor_manager = CursorManager()
        load_dotenv()
        mongo_uri = os.getenv("MONGO_URI")
        self.client = MongoClient(mongo_uri)
        self.db = self.client["subdomain_db"]
        self.collection = self.db["subdomains"]

    def _fetch_from_source(self, source, domain):
        try:
            found = source.fetch(domain)
            return DomainValidator.filter_valid_subdomains(found, domain)
        except Exception:
            return set()

    def save_subdomains(self, domain, subdomains):
        if subdomains:
            self.collection.update_one(
                {"domain": domain},
                {"$set": {"subdomains": list(subdomains), "last_updated": datetime.datetime.utcnow()}},
                upsert=True
            )

    def process_domain(self, domain, sources, total):
        if not DomainValidator.is_valid_domain(domain):
            self.completed += 1
            return set()

        self.console.print_domain_start(domain)
        self.console.print_progress(self.completed, total)
        
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(self._fetch_from_source, source, domain) for source in sources]
            results = [f.result() for f in as_completed(futures)]

        subdomains = set().union(*results) if results else set()

        self.console.update_domain_stats(domain, len(subdomains))
        self.console.print_domain_complete(domain, len(subdomains))
        self.save_subdomains(domain, subdomains)

        self.completed += 1
        self.console.print_progress(self.completed, total)
        return subdomains

    def run(self, domains, sources):
        if not domains:
            self.console.print_error("No valid domains provided")
            return

        self.completed = 0
        all_subdomains = set()
        total = len(domains)

        with self.cursor_manager:
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(self.process_domain, domain, sources, total) for domain in domains]
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        all_subdomains.update(result)
                    except Exception as e:
                        self.console.print(f"Error processing domain: {str(e)}")

            self.console.print_final_summary("MongoDB")
            return all_subdomains

def main():
    sources = get_sources()
    with open("domain.txt", 'r') as f:
        domains = [d.strip() for d in f if DomainValidator.is_valid_domain(d.strip())]
    
    subfinder = SubFinder()
    subfinder.run(domains, sources)

if __name__ == "__main__":
    main()