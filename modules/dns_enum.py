import concurrent.futures
import random
import socket
from typing import Any, Dict, List, Optional

import dns.exception
import dns.query
import dns.rdataclass
import dns.resolver
import dns.zone

from utils.logger import Logger
from utils.wordlists import load_wordlist

logger = Logger()


def _query(domain: str, rtype: str, resolver: dns.resolver.Resolver) -> List[Dict[str, Any]]:
    """
    Query DNS records of specific type for a domain.
    """
    try:
        answers = resolver.resolve(domain, rtype)
        ttl = int(answers.rrset.ttl) if answers.rrset is not None else None
        cls_txt = dns.rdataclass.to_text(answers.rrset.rdclass) if answers.rrset is not None else "IN"

        out: List[Dict[str, Any]] = []
        for r in answers:
            out.append({"value": r.to_text(), "ttl": ttl, "class": cls_txt})
        return out

    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []
    except Exception as e:
        logger.warning(f"Resolve error {domain} ({rtype}): {e}")
        return []


def resolve_subdomain(subdomain: str, record_types: List[str]) -> Optional[Dict[str, Any]]:
    """
    Resolve multiple DNS record types for a given subdomain.
    """
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
    """
    Detect if domain uses wildcard DNS.
    """
    fake = f"{random.randint(1000,9999)}.nonexistent.{target}"
    try:
        socket.gethostbyname(fake)
        return True
    except socket.gaierror:
        return False


def check_axfr(target: str, nameservers: List[str]) -> List[str]:
    """
    Attempt DNS zone transfer (AXFR) on discovered nameservers.
    """
    leaked_domains: List[str] = []
    for ns in nameservers:
        try:
            ns_host = ns.split()[-1] if " " in ns else ns
            logger.info(f"[*] Trying AXFR on {target} via {ns_host}")
            zone = dns.zone.from_xfr(dns.query.xfr(ns_host, target, timeout=5))
            for name, node in zone.nodes.items():
                leaked_domains.append(str(name))
            logger.success(f"[+] Zone transfer SUCCESS on {ns_host} ({len(leaked_domains)} records leaked)")
        except Exception as e:
            logger.warning(f"[-] Zone transfer failed on {ns}: {e}")
    return leaked_domains


def run(
    target: str,
    wordlist_path: str = None,
    threads: int = 10,
    output_format: str = "json",
    output_file: str = "results.json",
    dns_records: List[str] = None,
):

    if not dns_records:
        dns_records = [
            "A",
            "AAAA",
            "MX",
            "NS",
            "CNAME",
            "TXT",
            "SOA",
            "PTR",
            "SRV",
            "CAA",
            "DNSKEY",
            "RRSIG",
        ]

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

    ns_records = []
    try:
        ns_answers = dns.resolver.resolve(target, "NS")
        ns_records = [ns.to_text() for ns in ns_answers]
    except Exception:
        pass

    if ns_records:
        leaked = check_axfr(target, ns_records)
        if leaked:
            results["zone_transfer"] = leaked

    dnssec_info: Dict[str, Any] = {}
    for rtype in ["DNSKEY", "RRSIG"]:
        try:
            resolver = dns.resolver.Resolver()
            records = _query(target, rtype, resolver)
            if records:
                dnssec_info[rtype] = records
        except Exception:
            continue

    if dnssec_info:
        results["dnssec"] = dnssec_info

    if not results["subdomains"]:
        logger.error("No valid subdomains found")

    return results
