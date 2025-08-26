from core.aggregator import Aggregator
from core.reporting import Reporter
from modules import dns_enum
from utils.logger import Logger


class Controller:
    def __init__(self, args):
        self.args = args
        self.aggregator = Aggregator()
        self.logger = Logger()
        
    def run(self):
        self.logger.info(f"Target: {self.args.target}")
        modules = self.args.modules or ["dns_enum"]
        
        if "dns_enum" in modules:
            self.logger.info("Running DNS / Subdomain Enumeration...")
            self.aggregator.add("dns_enum", dns_enum.run(self.args.target, wordlist_path=self.args.wordlist, threads=self.args.threads))
            
        Reporter.save(self.aggregator.get_results(), self.args.output)
            
        
        