import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from rich.progress import Progress
from urllib3.util.retry import Retry

from utils.logger import global_console
from utils.logger import global_logger as logger
from utils.wordlists import load_wordlist

session = requests.Session()
retries = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"],
)
adapter = HTTPAdapter(max_retries=retries, pool_connections=100, pool_maxsize=100)
session.mount("http://", adapter)
session.mount("https://", adapter)

DEFAULT_TIMEOUT = 10


def safe_request(method, url, **kwargs):
    """Wrapper untuk session request dengan timeout default"""
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    return session.request(method, url, **kwargs)


def crawl_links(base_url, max_depth=2, visited=None, filter_tag="endpoint"):
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
        r = safe_request("GET", base_url)
        if "text/html" not in r.headers.get("Content-Type", ""):
            return []

        soup = BeautifulSoup(r.text, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(base_url, href)
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                if logger.level == "DEBUG":
                    logger.info(f"[CRAWL/{filter_tag}] Found link: {full_url}")
                endpoints.append(full_url)
                endpoints.extend(crawl_links(full_url, max_depth=max_depth - 1, visited=visited))
    except Exception as e:
        logger.warning(f"[CRAWL/{filter_tag}] Failed to crawl {base_url} ({e})")

    return list(set(endpoints))


def extract_js_endpoints(base_url, filter_tag="endpoint"):
    """
    Search for endpoints in JavaScript files.
    """
    endpoints = []
    try:
        r = safe_request("GET", base_url)
        js_files = re.findall(r'src=["\'](.*?\.js)["\']', r.text)

        for js in js_files:
            js_url = urljoin(base_url, js)
            if logger.level == "DEBUG":
                logger.info(f"[JS/{filter_tag}] Found JS file: {js_url}")
            try:
                js_resp = safe_request("GET", js_url)
                found = re.findall(r"\/[A-Za-z0-9_\-\/]+", js_resp.text)
                for f in found:
                    if f.startswith("/"):
                        full = urljoin(base_url, f)
                        endpoints.append(full)
                        if logger.level == "DEBUG":
                            logger.info(f"[JS/{filter_tag}] Extracted endpoint: {full}")
            except Exception as e:
                logger.warning(f"[JS/{filter_tag}] Failed to fetch {js_url} ({e})")

    except Exception as e:
        logger.warning(f"[JS/{filter_tag}] Failed to fetch base page {base_url} ({e})")

    return list(set(endpoints))


def fuzz_endpoints(base_url, wordlist_path=None, threads=10, filter_tag="endpoint"):
    """
    Use wordlist for path fuzzing
    """
    endpoints = []
    wordlist = load_wordlist(wordlist_path)

    def check_path(path):
        path = path.lstrip("/")
        test_url = urljoin(base_url, path)
        try:
            r = safe_request("GET", test_url)
            if r.status_code not in [404]:
                if logger.level == "DEBUG":
                    logger.info(f"[FUZZ/{filter_tag}] Found {test_url} ({r.status_code})")
                return test_url
        except Exception as e:
            if logger.level == "DEBUG":
                logger.warning(f"[FUZZ/{filter_tag}] Error {test_url}: {e}")
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


def check_http_methods(url, filter_tag="endpoint"):
    """
    Hybrid HTTP method checker
    """
    methods = ["GET"]
    candidates = ["POST", "PUT", "DELETE", "PATCH"]

    allowed_from_options = []

    try:
        r = safe_request("OPTIONS", url)
        allow = r.headers.get("Allow", "")
        if allow:
            allowed_from_options = [m.strip().upper() for m in allow.split(",")]
            methods.extend([m for m in candidates if m in allowed_from_options])
            if logger.level == "DEBUG":
                logger.info(f"[METHODS/{filter_tag}] {url} allows: {', '.join(allowed_from_options)}")
    except Exception:
        pass

    if not allowed_from_options:
        try:
            baseline = safe_request("GET", url)
            baseline_sig = (baseline.status_code, len(baseline.content))

            for m in candidates:
                try:
                    test = safe_request(m, url)
                    sig = (test.status_code, len(test.content))
                    if test.status_code not in [405, 501] and sig != baseline_sig:
                        methods.append(m)
                        if logger.level == "DEBUG":
                            logger.info(f"[METHODS/{filter_tag}] {url} supports {m}")
                except Exception:
                    continue
        except Exception:
            pass

    return list(set(methods))


def analyze_endpoints(endpoints, threads=10, limit=1000, filter_tag="endpoint"):
    """
    Analyze endpoints for status code, content length, and allowed methods.
    """
    results = []

    def check_endpoint(ep):
        try:
            r = safe_request("GET", ep)
            size = len(r.content)
            methods = check_http_methods(ep, filter_tag=filter_tag)
            if logger.level == "DEBUG":
                logger.info(
                    f"[ANALYZE/{filter_tag}] {ep}\n"
                    f"   └─ Status : {r.status_code}\n"
                    f"   └─ Length : {size} bytes\n"
                    f"   └─ Methods: {', '.join(methods)}"
                )
            return {
                "url": str(ep),
                "status": str(r.status_code),
                "length": str(size),
                "methods": [str(m) for m in methods],
            }
        except Exception as e:
            if logger.level == "DEBUG":
                logger.warning(f"[ANALYZE/{filter_tag}] Error fetching {ep}: {e}")
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


def run(target, wordlist=None, threads=10, filters=None, base_path=None, logger=logger):
    """
    Run endpoint enumeration
    """
    base_url = f"http://{target}" if not target.startswith("http") else target

    # Handle base path
    if base_path:
        if not base_path.startswith("/"):
            base_path = "/" + base_path
        base_url = base_url.rstrip("/") + base_path
        if not base_url.endswith("/"):
            base_url += "/"

    filter_tag = filters[0] if filters else "endpoint"

    logger.info(f"Starting endpoint enumeration on {base_url} [Filter: {filter_tag}]")

    endpoints = set()

    # Stage 1: Crawl
    logger.info("[CRAWL] Searching for internal links...")
    crawled = crawl_links(base_url, max_depth=1, filter_tag=filter_tag)
    logger.success(f"Found {len(crawled)} endpoints via crawling")
    endpoints.update(crawled)

    # Stage 2: JS Extraction
    logger.info("[JS] Extracting endpoints from JavaScript...")
    js_eps = extract_js_endpoints(base_url, filter_tag=filter_tag)
    logger.success(f"Extracted {len(js_eps)} endpoints from JS files")
    endpoints.update(js_eps)

    # Stage 3: Fuzzing
    if wordlist:
        logger.info("[FUZZ] Running wordlist fuzzing...")
        fuzzed = fuzz_endpoints(base_url, wordlist, threads=threads, filter_tag=filter_tag)
        logger.success(f"Found {len(fuzzed)} endpoints using custom wordlist")
        endpoints.update(fuzzed)
    else:
        logger.warning("[FUZZ] No wordlist provided. Skipping fuzzing...")

    # Stage 4: Analyze
    logger.info("[ANALYZE] Checking status codes, lengths, and HTTP methods...")
    results = analyze_endpoints(list(endpoints), threads=threads, limit=2000, filter_tag=filter_tag)
    logger.success(f"Final valid endpoints: {len(results)}")

    return {
        "filters": filters or [],
        "endpoints": results,
    }
