import concurrent.futures
import random
import socket
import dns.resolver

from utils.logger import Logger
from utils.wordlists import load_wordlist

logger = Logger()

def resolve_subdomain(subdomain: str, record_types: list[str]):
    results = {"subdomain": subdomain, "records": {}}
    resolver = dns.resolver.Resolver()
    
    for rtype in record_types:
        try:
            answers = resolver.resolve(subdomain, rtype)
            results["records"][rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            results["records"][rtype] = []
        except Exception as e:
            logger.error(f"Error resolving {subdomain} for {rtype}: {e}")
            results["records"][rtype] = []
            
    if any(results["records"].values()):
        return results
    return None

def detect_wildcard(target: str):
    fake = f"{random.randint(1000,9999)}.nonexistent.{target}"
    try:
        socket.gethostbyname(fake)
        return True
    except socket.gaierror:
        return False

def run(target: str, wordlist_path: str = None, threads: int = 10, 
        output_format: str = "json", output_file: str = "results.json",
        dns_records: list[str]=None):
    
    if not dns_records:
        dns_records = ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]
    
    results = {"subdomains": []}
    wordlist = load_wordlist(wordlist_path)

    logger.info(f"Starting DNS Enumeration for: {target}")
    logger.info(f"Wordlist loaded: {len(wordlist)} entries")
    logger.info(f"DNS Record Types: {', '.join(dns_records)}")

    if detect_wildcard(target):
        logger.warning("Wildcard DNS detected! Results may contain false positives")

    subdomains = [f"{sub}.{target}" for sub in wordlist]

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(resolve_subdomain, sub, dns_records) for sub in subdomains]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                sub = result["subdomain"]
                logger.success(f"Found: {sub}")
                for rtype, records in result["records"].items():
                    for r in records:
                        logger.success(f"   {rtype} → {r}")
                results["subdomains"].append(result)

    if not results["subdomains"]:
        logger.error("No valid subdomains found")

    return results
