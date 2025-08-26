from core.aggregator import Aggregator
from core.reporting import Reporter
from utils.logger import Logger
from modules import dns_enum

class Controller:
    def __init__(self, args):
        self.args = args
        self.aggregator = Aggregator()
        self.logger = Logger()

    def run(self):
        self.logger.info(f"🎯 Target: {self.args.target}")
        modules = self.args.modules or ["dns"]

        if "dns" in modules:
            self.logger.info("Running DNS / Subdomain Enumeration...")
            self.aggregator.add("dns", dns_enum.run(
                self.args.target,
                wordlist_path=self.args.wordlist,
                threads=self.args.threads
            ))

        Reporter.save(self.aggregator.get_results(), self.args.output)
