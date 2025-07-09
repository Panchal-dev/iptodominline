import os
import psycopg2
from concurrent.futures import ThreadPoolExecutor, as_completed
from console import SubFinderConsole
from sources import get_sources
from utils import DomainValidator, CursorManager

class SubFinder:
    def __init__(self, db_params):
        self.console = SubFinderConsole()
        self.completed = 0
        self.cursor_manager = CursorManager()
        self.db_params = db_params
        self._init_db()

    def _init_db(self):
        with psycopg2.connect(**self.db_params) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS subdomains (
                        id SERIAL PRIMARY KEY,
                        domain VARCHAR(255) NOT NULL,
                        subdomain VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_domain ON subdomains (domain);
                """)
                conn.commit()

    def _fetch_from_source(self, source, domain):
        try:
            found = source.fetch(domain)
            return DomainValidator.filter_valid_subdomains(found, domain)
        except Exception:
            return set()

    def save_subdomains(self, subdomains, domain):
        if subdomains:
            with psycopg2.connect(**self.db_params) as conn:
                with conn.cursor() as cur:
                    for subdomain in sorted(subdomains):
                        cur.execute(
                            "INSERT INTO subdomains (domain, subdomain) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                            (domain, subdomain)
                        )
                    conn.commit()

    def process_domain(self, domain, sources, total):
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
        self.save_subdomains(subdomains, domain)

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
                futures = [
                    executor.submit(self.process_domain, domain, sources, total)
                    for domain in domains
                ]
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        all_subdomains.update(result)
                    except Exception as e:
                        self.console.print(f"Error processing domain: {str(e)}")

            self.console.print_final_summary("PostgreSQL database")
            return all_subdomains

def main():
    # Load database parameters from environment variables
    db_params = {
        "dbname": os.getenv("DB_NAME"),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASSWORD"),
        "host": os.getenv("DB_HOST"),
        "port": os.getenv("DB_PORT", "5432")
    }

    # Read domains from domain.txt
    with open("domain.txt", "r") as f:
        domains = [d.strip() for d in f if DomainValidator.is_valid_domain(d.strip())]

    sources = get_sources()
    subfinder = SubFinder(db_params)
    subfinder.run(domains, sources)

if __name__ == "__main__":
    main()  