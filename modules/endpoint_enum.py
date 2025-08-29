import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from rich.progress import Progress

from utils.logger import global_console
from utils.logger import global_logger as logger
from utils.wordlists import load_wordlist


def crawl_links(base_url, max_depth=2, visited=None):
    """
    Crawl page for search internal links
    """
    if visited is None:
        visited = set()

    if base_url in visited or max_depth <= 0:
        return []

    visited.add(base_url)
    endpoints = []

    try:
        r = requests.get(base_url, timeout=5)
        if "text/html" not in r.headers.get("Content-Type", ""):
            return []

        soup = BeautifulSoup(r.text, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(base_url, href)
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                if logger.level == "DEBUG":
                    logger.info(f"[Crawl] Found link: {full_url}")
                endpoints.append(full_url)
                endpoints.extend(crawl_links(full_url, max_depth=max_depth - 1, visited=visited))
    except Exception as e:
        logger.warning(f"Failed to fetch {base_url} ({e})")

    return list(set(endpoints))


def extract_js_endpoints(base_url):
    """
    Search for endpoints in JavaScript files.
    """
    endpoints = []
    try:
        r = requests.get(base_url, timeout=5)
        js_files = re.findall(r'src=["\'](.*?\.js)["\']', r.text)

        for js in js_files:
            js_url = urljoin(base_url, js)
            if logger.level == "DEBUG":
                logger.info(f"[JS] Checking {js_url}")
            try:
                js_resp = requests.get(js_url, timeout=5)
                found = re.findall(r"\/[A-Za-z0-9_\-\/]+", js_resp.text)
                for f in found:
                    if f.startswith("/"):
                        full = urljoin(base_url, f)
                        endpoints.append(full)
                        if logger.level == "DEBUG":
                            logger.info(f"[JS] Extracted endpoint: {full}")
            except Exception as e:
                logger.warning(f"Failed to fetch {js_url} ({e})")

    except Exception as e:
        logger.warning(f"Failed to fetch {base_url} ({e})")

    return list(set(endpoints))


def fuzz_endpoints(base_url, wordlist_path=None, threads=10):
    """
    Use wordlist for path fuzzing
    """
    endpoints = []
    wordlist = load_wordlist(wordlist_path)

    def check_path(path):
        test_url = urljoin(base_url, path)
        try:
            r = requests.get(test_url, timeout=3)
            if r.status_code not in [404]:
                if logger.level == "DEBUG":
                    logger.info(f"[Fuzz] Found {test_url} ({r.status_code})")
                return test_url
        except Exception as e:
            if logger.level == "DEBUG":
                logger.warning(f"[Fuzz] Error {test_url}: {e}")
            return None
        return None

    with (
        ThreadPoolExecutor(max_workers=threads) as executor,
        Progress(console=global_console, transient=True) as progress,
    ):
        task = progress.add_task("[cyan]Fuzzing endpoints...", total=len(wordlist))
        futures = [executor.submit(check_path, path) for path in wordlist]

        for f in as_completed(futures):
            url = f.result()
            if url:
                endpoints.append(url)
            progress.update(task, advance=1)

    return endpoints


def check_http_methods(url):
    """
    Hybrid HTTP method checker
    """
    methods = ["GET"]
    candidates = ["POST", "PUT", "DELETE", "PATCH"]

    allowed_from_options = []

    try:
        r = requests.options(url, timeout=3)
        allow = r.headers.get("Allow", "")
        if allow:
            allowed_from_options = [m.strip().upper() for m in allow.split(",")]
            methods.extend([m for m in candidates if m in allowed_from_options])
            if logger.level == "DEBUG":
                logger.info(f"[Methods] {url} -> Allow header: {allowed_from_options}")
    except Exception as e:
        if logger.level == "DEBUG":
            logger.warning(f"[Methods] OPTIONS failed for {url}: {e}")

    if not allowed_from_options:
        try:
            baseline = requests.get(url, timeout=3)
            baseline_sig = (baseline.status_code, len(baseline.content))

            for m in candidates:
                try:
                    test = requests.request(m, url, timeout=3)
                    sig = (test.status_code, len(test.content))

                    if test.status_code not in [405, 501] and sig != baseline_sig:
                        methods.append(m)
                        if logger.level == "DEBUG":
                            logger.info(f"[Methods] {url} -> supports {m}")
                except Exception as e:
                    if logger.level == "DEBUG":
                        logger.warning(f"[Methods] Error testing {m} on {url}: {e}")
                    continue
        except Exception as e:
            if logger.level == "DEBUG":
                logger.warning(f"[Methods] Baseline GET failed for {url}: {e}")

    return list(set(methods))


def analyze_endpoints(endpoints, threads=10, limit=1000):
    """
    Analyze endpoints for status code, content length, and allowed methods.
    """
    results = []

    def check_endpoint(ep):
        try:
            r = requests.get(ep, timeout=3)
            size = len(r.content)
            methods = check_http_methods(ep)
            if logger.level == "DEBUG":
                logger.info(f"[Analyze] {ep} -> {r.status_code}, {size} bytes, Methods={methods}")
            return {
                "url": str(ep),
                "status": str(r.status_code),
                "length": str(size),
                "methods": [str(m) for m in methods],
            }
        except Exception as e:
            if logger.level == "DEBUG":
                logger.warning(f"[Analyze] Error fetching {ep}: {e}")
            return {"url": str(ep), "status": "Error", "length": "0", "methods": []}

    with (
        ThreadPoolExecutor(max_workers=threads) as executor,
        Progress(console=global_console, transient=True) as progress,
    ):
        task = progress.add_task("[cyan]Analyzing endpoints...", total=min(len(endpoints), limit))
        futures = [executor.submit(check_endpoint, ep) for ep in endpoints[:limit]]

        for f in as_completed(futures):
            results.append(f.result())
            progress.update(task, advance=1)

    return results


def run(target, wordlist=None, threads=10, logger=logger):
    """
    Run endpoint enumeration
    """
    base_url = f"http://{target}" if not target.startswith("http") else target
    logger.info(f"Starting basic discovery on {base_url}")

    endpoints = set()

    crawled = crawl_links(base_url, max_depth=1)
    logger.success(f"Crawled {len(crawled)} endpoints")
    endpoints.update(crawled)

    js_eps = extract_js_endpoints(base_url)
    logger.success(f"Extracted {len(js_eps)} endpoints from JS")
    endpoints.update(js_eps)

    fuzzed = fuzz_endpoints(base_url, wordlist, threads=threads)
    logger.success(f"Fuzzed {len(fuzzed)} potential endpoints")
    endpoints.update(fuzzed)

    results = analyze_endpoints(list(endpoints), threads=threads, limit=2000)
    logger.success(f"Final valid endpoints: {len(results)}")

    return {"endpoints": results}
