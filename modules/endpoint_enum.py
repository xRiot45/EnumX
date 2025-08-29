import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import global_logger as logger
from utils.logger import global_console
from utils.wordlists import load_wordlist
from rich.progress import Progress


def crawl_links(base_url, max_depth=2, visited=None):
    """Crawl halaman untuk mencari link internal."""
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
                endpoints.append(full_url)
                endpoints.extend(crawl_links(full_url, max_depth=max_depth - 1, visited=visited))
    except Exception as e:
        logger.warning(f"[Endpoint:Crawler] Failed to fetch {base_url} ({e})")

    return list(set(endpoints))


def extract_js_endpoints(base_url):
    """Cari endpoint di file JavaScript."""
    endpoints = []
    try:
        r = requests.get(base_url, timeout=5)
        js_files = re.findall(r'src=["\'](.*?\.js)["\']', r.text)

        for js in js_files:
            js_url = urljoin(base_url, js)
            try:
                js_resp = requests.get(js_url, timeout=5)
                found = re.findall(r'\/[A-Za-z0-9_\-\/]+', js_resp.text)
                endpoints.extend([urljoin(base_url, f) for f in found if f.startswith("/")])
            except Exception as e:
                logger.warning(f"[Endpoint:JS] Failed to fetch {js_url} ({e})")

    except Exception as e:
        logger.warning(f"[Endpoint:JS] Failed to fetch {base_url} ({e})")

    return list(set(endpoints))


def fuzz_endpoints(base_url, wordlist_path=None, threads=10):
    """Gunakan wordlist untuk path fuzzing (multithreaded + progress bar)."""
    endpoints = []
    wordlist = load_wordlist(wordlist_path)

    def check_path(path):
        test_url = urljoin(base_url, path)
        try:
            r = requests.get(test_url, timeout=3)
            if r.status_code not in [404]:
                return test_url
        except Exception:
            return None
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor, Progress(console=global_console, transient=True) as progress:
        task = progress.add_task("[cyan]Fuzzing endpoints...", total=len(wordlist))
        futures = [executor.submit(check_path, path) for path in wordlist]

        for f in as_completed(futures):
            url = f.result()
            if url:
                endpoints.append(url)
            progress.update(task, advance=1)

    return endpoints


def check_http_methods(url):
    """Cek metode HTTP yang diizinkan dengan OPTIONS."""
    methods = ["GET"]
    try:
        r = requests.options(url, timeout=3)
        allow = r.headers.get("Allow", "")
        if allow:
            for m in ["POST", "PUT", "DELETE", "PATCH"]:
                if m in allow:
                    methods.append(m)
    except Exception:
        pass
    return list(set(methods))


def analyze_endpoints(endpoints, threads=10, limit=1000):
    """Ambil status code & response size (multithreaded + progress bar)."""
    results = []

    def check_endpoint(ep):
        try:
            r = requests.get(ep, timeout=3)
            size = len(r.content)
            methods = check_http_methods(ep)
            return {"url": ep, "status": r.status_code, "length": size, "methods": methods}
        except Exception:
            return {"url": ep, "status": "Error", "length": 0, "methods": []}

    with ThreadPoolExecutor(max_workers=threads) as executor, Progress(console=global_console, transient=True) as progress:
        task = progress.add_task("[cyan]Analyzing endpoints...", total=min(len(endpoints), limit))
        futures = [executor.submit(check_endpoint, ep) for ep in endpoints[:limit]]

        for f in as_completed(futures):
            results.append(f.result())
            progress.update(task, advance=1)

    return results


def run(target, wordlist=None, threads=10, logger=logger):
    """Stage 1 – Basic Endpoint Discovery"""
    base_url = f"http://{target}" if not target.startswith("http") else target
    logger.info(f"[Endpoint] Starting basic discovery on {base_url}")

    endpoints = set()

    # Crawl halaman
    crawled = crawl_links(base_url, max_depth=1)
    logger.success(f"[Endpoint] Crawled {len(crawled)} endpoints")
    endpoints.update(crawled)

    # Extract dari JS
    js_eps = extract_js_endpoints(base_url)
    logger.success(f"[Endpoint] Extracted {len(js_eps)} endpoints from JS")
    endpoints.update(js_eps)

    # Fuzzing
    fuzzed = fuzz_endpoints(base_url, wordlist, threads=threads)
    logger.success(f"[Endpoint] Fuzzed {len(fuzzed)} potential endpoints")
    endpoints.update(fuzzed)

    # Analisis
    results = analyze_endpoints(list(endpoints), threads=threads, limit=2000)
    logger.success(f"[Endpoint] Final valid endpoints: {len(results)}")

    return {"endpoints": results}
