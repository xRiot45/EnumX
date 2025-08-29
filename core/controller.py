from rich.console import Console
from rich.table import Table

from core.aggregator import Aggregator
from core.reporting import Reporting
from modules import dns_enum, endpoint_enum
from utils.logger import global_logger as logger


class Controller:
    def __init__(self, args):
        self.args = args
        self.aggregator = Aggregator()
        self.logger = logger

        if getattr(args, "silent", False):
            self.logger.set_level("SILENT")
        elif getattr(args, "verbose", False):
            self.logger.set_level("DEBUG")
        else:
            self.logger.set_level("INFO")

        # Normalize DNS record filters
        VALID_CHOICES = {"A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "PTR", "SRV", "CAA", "DNSKEY", "RRSIG"}

        raw_filters = None
        if getattr(self.args, "filter_dns", None):
            raw_filters = self.args.filter_dns
        elif getattr(self.args, "dns_records", None):
            raw_filters = self.args.dns_records

        if raw_filters:
            normalized = []
            for item in raw_filters:
                for r in str(item).split(","):
                    r = r.strip().upper()
                    if not r:
                        continue
                    if r == "ALL":
                        normalized.extend(list(VALID_CHOICES))
                    else:
                        normalized.append(r)
            self.args.dns_records = sorted(set([r for r in normalized if r in VALID_CHOICES]))
            if not self.args.dns_records:
                self.args.dns_records = sorted(VALID_CHOICES)
        else:
            self.args.dns_records = sorted(VALID_CHOICES)

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
                dns_records=getattr(self.args, "dns_records", None),
                logger=self.logger,
            )
            self.aggregator.add("dns", dns_results)

            if not getattr(self.args, "silent", False):
                console = Console()
                table = Table(title=f"DNS Enumeration Results for {self.args.target}")

                table.add_column("Subdomain", style="cyan", no_wrap=True)
                table.add_column("Record Type", style="magenta")
                table.add_column("Class", style="green")
                table.add_column("TTL", style="yellow")
                table.add_column("Value", style="white")

                filters = (
                    set([r.upper() for r in getattr(self.args, "dns_records", [])])
                    if getattr(self.args, "dns_records", None)
                    else None
                )

                for entry in dns_results.get("subdomains", []):
                    sub = entry["subdomain"]
                    for rtype, values in entry.get("records", {}).items():
                        if filters and rtype not in filters:
                            continue
                        for val in values:
                            table.add_row(
                                sub, rtype, val.get("class", "IN"), str(val.get("ttl", "")), val.get("value", "")
                            )

                console.print(table)

        elif "endpoint" in modules:
            self.logger.info("Running Endpoint Enumeration...")
            endpoint_results = endpoint_enum.run(self.args.target, wordlist=self.args.wordlist, logger=self.logger)
            self.aggregator.add("endpoint", endpoint_results)

            if not getattr(self.args, "silent", False):
                console = Console()
                table = Table(title=f"Endpoint Enumeration Results for {self.args.target}")

                table.add_column("URL", style="cyan", no_wrap=True)
                table.add_column("Status", style="magenta")
                table.add_column("Length", style="green")
                table.add_column("Methods", style="yellow")

                for entry in endpoint_results.get("endpoints", []):
                    table.add_row(entry["url"], str(entry["status"]), str(entry["length"]), ", ".join(entry["methods"]))

                console.print(table)

        else:
            self.logger.warning("No valid modules selected. Exiting.")
            return

        Reporting.save(self.aggregator.get_results(), self.args.output, self.args.format)
