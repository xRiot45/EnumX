import concurrent.futures
import random
import socket
import os
from typing import Any, Dict, List, Optional

import dns.exception
import dns.query
import dns.rdataclass
import dns.resolver
import dns.zone
import requests
from rich.progress import Progress
from dotenv import load_dotenv  # <<<< tambahan

from utils.logger import global_console
from utils.logger import global_logger as logger
from utils.wordlists import load_wordlist

# --- Load environment variables (.env) ---
load_dotenv()


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
        if rtype.upper() == "ALL":
            continue

        items = _query(subdomain, rtype, resolver)
        if items:
            records[rtype] = items

    if records:
        if logger.level == "DEBUG":
            logger.info(f"Resolved {subdomain} ({', '.join(records.keys())})")
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


def passive_crtsh(domain: str) -> List[str]:
    """
    Passive OSINT using crt.sh to gather additional subdomains.
    """
    subdomains: List[str] = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value")
                if name and "*" not in name:
                    for n in name.split("\n"):
                        if n.endswith(domain):
                            subdomains.append(n.strip())
        else:
            logger.warning(f"crt.sh returned {resp.status_code}")
    except Exception as e:
        logger.warning(f"crt.sh error: {e}")
    return list(set(subdomains))


def passive_virustotal(domain: str, api_key: str) -> List[str]:
    """
    Passive OSINT using VirusTotal API to gather additional subdomains.
    """
    subdomains: List[str] = []
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data:
                for entry in data["data"]:
                    name = entry.get("id")
                    if name and name.endswith(domain):
                        subdomains.append(name.strip())
        else:
            logger.warning(f"VirusTotal returned {resp.status_code}: {resp.text}")
    except Exception as e:
        logger.warning(f"VirusTotal error: {e}")

    return list(set(subdomains))


def run(
    target: str,
    wordlist_path: str = None,
    threads: int = 10,
    output_format: str = "json",
    output_file: str = "results.json",
    dns_records: List[str] = None,
    logger=None,
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

    # --- Load from wordlist ---
    wordlist = load_wordlist(wordlist_path)
    subdomains = [f"{sub}.{target}" for sub in wordlist]

    # --- Passive OSINT ---
    passive = passive_crtsh(target)

    # VirusTotal passive
    vt_api_key = os.getenv("VT_API_KEY")
    if vt_api_key:
        vt_passive = passive_virustotal(target, vt_api_key)
        if vt_passive:
            logger.info(f"[Passive] Found {len(vt_passive)} subdomains from VirusTotal")
            passive.extend(vt_passive)
    else:
        logger.warning("VirusTotal API key not found in .env, skipping VT passive enumeration")

    if passive:
        logger.info(f"[Passive] Found total {len(passive)} subdomains (crt.sh + VirusTotal)")
        subdomains.extend(passive)

    subdomains = list(set(subdomains))
    logger.info(f"Starting DNS enumeration on {target} with {len(subdomains)} subdomains...")

    if detect_wildcard(target):
        logger.warning("Wildcard DNS detected! Results may contain false positives")

    results: Dict[str, Any] = {"subdomains": []}
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)

    if logger.level == "SILENT":
        with (
            executor as ex,
            Progress(console=global_console, transient=True, redirect_stdout=False, redirect_stderr=False) as progress,
        ):
            task = progress.add_task("[cyan]Resolving subdomains...", total=len(subdomains))
            futures = [ex.submit(resolve_subdomain, s, dns_records) for s in subdomains]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    results["subdomains"].append(res)
                progress.update(task, advance=1)
    else:
        with executor as ex, Progress(console=global_console, transient=True) as progress:
            task = progress.add_task("[cyan]Resolving subdomains...", total=len(subdomains))
            futures = [ex.submit(resolve_subdomain, s, dns_records) for s in subdomains]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    results["subdomains"].append(res)
                progress.update(task, advance=1)

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
