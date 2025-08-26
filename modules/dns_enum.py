import socket
import random
import concurrent.futures
from utils.logger import Logger
from utils.wordlists import load_wordlist

logger = Logger()

def resolve_subdomain(subdomain: str):
    try:
        ip = socket.gethostbyname(subdomain)
        return subdomain, ip
    except socket.gaierror:
        return None

def detect_wildcard(target: str):
    fake = f"{random.randint(1000,9999)}.nonexistent.{target}"
    try:
        socket.gethostbyname(fake)
        return True
    except socket.gaierror:
        return False

def run(target: str, wordlist_path: str = None, threads: int = 10):
    results = {"subdomains": []}
    wordlist = load_wordlist(wordlist_path)

    logger.info(f"🔍 Starting DNS Enumeration for: {target}")
    logger.info(f"📑 Wordlist loaded: {len(wordlist)} entries")

    if detect_wildcard(target):
        logger.warning("Wildcard DNS detected! Results may contain false positives")

    subdomains = [f"{sub}.{target}" for sub in wordlist]

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(resolve_subdomain, sub) for sub in subdomains]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                sub, ip = result
                logger.success(f"Found: {sub} → {ip}")
                results["subdomains"].append({"subdomain": sub, "ip": ip})

    if not results["subdomains"]:
        logger.error("No valid subdomains found")

    return results
