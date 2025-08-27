from rich.console import Console
from rich.table import Table

from core.aggregator import Aggregator
from core.reporting import Reporter
from modules import dns_enum
from utils.logger import Logger


class Controller:
    def __init__(self, args):
        self.args = args
        self.aggregator = Aggregator()
        self.logger = Logger()

        if getattr(args, "silent", False):
            self.logger.set_level("SILENT")
        elif getattr(args, "verbose", False):
            self.logger.set_level("DEBUG")
        else:
            self.logger.set_level("INFO")

        if hasattr(self.args, "dns_records"):
            normalized_records = []
            for item in self.args.dns_records:
                normalized_records.extend([r.strip().upper() for r in item.split(",") if r.strip()])

            valid_choices = {"A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "PTR"}
            self.args.dns_records = [r for r in normalized_records if r in valid_choices]

            if not self.args.dns_records:
                self.args.dns_records = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "PTR"]

    def run(self):
        self.logger.info(f"Target: {self.args.target}")
        modules = self.args.modules or ["dns"]

        if "dns" in modules:
            self.logger.info("Running DNS / Subdomain Enumeration...")
            dns_results = dns_enum.run(
                self.args.target,
                wordlist_path=self.args.wordlist,
                threads=self.args.threads,
                output_format=self.args.format,
                output_file=self.args.output,
                dns_records=self.args.filter,
                logger=self.logger,
            )
            self.aggregator.add("dns", dns_results)

            console = Console()
            table = Table(title=f"DNS Enumeration Results for {self.args.target}")

            table.add_column("Subdomain", style="cyan", no_wrap=True)
            table.add_column("Record Type", style="magenta")
            table.add_column("Class", style="green")
            table.add_column("TTL", style="yellow")
            table.add_column("Value", style="white")

            filters = (
                set([r.upper() for r in getattr(self.args, "filter", [])])
                if getattr(self.args, "filter", None)
                else None
            )

            for entry in dns_results.get("subdomains", []):
                sub = entry["subdomain"]
                for rtype, values in entry.get("records", {}).items():
                    if filters and rtype not in filters:
                        continue
                for val in values:
                    table.add_row(sub, rtype, val.get("class", "IN"), str(val.get("ttl", "")), val.get("value", ""))

            console.print(table)

        Reporter.save(self.aggregator.get_results(), self.args.output, self.args.format)
