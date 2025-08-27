from core.aggregator import Aggregator
from core.reporting import Reporter
from modules import dns_enum
from utils.logger import Logger


class Controller:
    def __init__(self, args):
        self.args = args
        self.aggregator = Aggregator()
        self.logger = Logger()

        if hasattr(self.args, "dns_records"):
            normalized_records = []
            for item in self.args.dns_records:
                normalized_records.extend([r.strip().upper() for r in item.split(",") if r.strip()])

            valid_choices = {"A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "PTR"}
            self.args.dns_records = [r for r in normalized_records if r in valid_choices]

            if not self.args.dns_records:
                self.args.dns_records = [
                    "A",
                    "AAAA",
                    "MX",
                    "NS",
                    "CNAME",
                    "TXT",
                    "SOA",
                    "PTR",
                ]

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
                dns_records=self.args.dns_records,
            )
            self.aggregator.add("dns", dns_results)

        Reporter.save(self.aggregator.get_results(), self.args.output, self.args.format)
