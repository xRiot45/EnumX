# modules/dns_enum.py
import concurrent.futures
import random
import socket
from typing import List, Dict, Any, Optional

import dns.resolver
import dns.rdataclass
import dns.exception

from utils.logger import Logger
from utils.wordlists import load_wordlist

logger = Logger()


def _query(domain: str, rtype: str, resolver: dns.resolver.Resolver) -> List[Dict[str, Any]]:
    try:
        answers = resolver.resolve(domain, rtype)
        ttl = int(answers.rrset.ttl) if answers.rrset is not None else None
        cls_txt = dns.rdataclass.to_text(answers.rrset.rdclass) if answers.rrset is not None else "IN"

        out: List[Dict[str, Any]] = []
        for r in answers:
            out.append({
                "value": r.to_text(),
                "ttl": ttl,
                "class": cls_txt
            })
        return out

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception as e:
        logger.warning(f"Resolve error {domain} ({rtype}): {e}")
        return []


def resolve_subdomain(subdomain: str, record_types: List[str]) -> Optional[Dict[str, Any]]:
    resolver = dns.resolver.Resolver()
    records: Dict[str, List[Dict[str, Any]]] = {}

    for rtype in record_types:
        items = _query(subdomain, rtype, resolver)
        if items:
            records[rtype] = items

    if records:
        return {"subdomain": subdomain, "records": records}
    return None


def detect_wildcard(target: str) -> bool:
    fake = f"{random.randint(1000,9999)}.nonexistent.{target}"
    try:
        socket.gethostbyname(fake)
        return True
    except socket.gaierror:
        return False


def run(target: str,
        wordlist_path: str = None,
        threads: int = 10,
        output_format: str = "json",
        output_file: str = "results.json",
        dns_records: List[str] = None):

    if not dns_records:
        dns_records = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "PTR"]

    wordlist = load_wordlist(wordlist_path)
    logger.info(f"Starting DNS enumeration on {target} with {len(wordlist)} subdomains...")

    if detect_wildcard(target):
        logger.warning("Wildcard DNS detected! Results may contain false positives")

    results: Dict[str, Any] = {"subdomains": []}
    subdomains = [f"{sub}.{target}" for sub in wordlist]

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(resolve_subdomain, s, dns_records) for s in subdomains]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                logger.success(f"Found: {res['subdomain']}")
                for rtype, items in res["records"].items():
                    for item in items:
                        logger.success(f"   {rtype} {item['class']} TTL={item['ttl']} → {item['value']}")
                results["subdomains"].append(res)

    if not results["subdomains"]:
        logger.error("No valid subdomains found")

    return results
