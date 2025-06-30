#!/usr/bin/env python3
import socket
import random
import itertools
import requests
import time
import json
import signal
import sys
import logging
import argparse
import asyncio
import aiohttp
from wordfreq import zipf_frequency
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tqdm import tqdm
from multiprocessing import Pool, cpu_count

# --- KONSTANTER --- #
NUM_CANDIDATES = 2500
MAX_LABEL_LEN = 4
TOP_TLD_COUNT = 200
HTML_OUT = 'domains.html'
JSONL_FILE = 'results.jsonl'
LOG_FILE = 'domain_scanner.log'
SORTED_LIST_FILE = 'sorted_domains.jsonl'
TLD_CACHE_FILE = 'tlds.json'
TLD_CACHE_MAX_AGE = 86400  # one day in seconds

throttle = 0.05  # pause mellem DNS-tjek
DNS_BATCH_SIZE = 50  # antal samtidige DNS-opslag


class DomainFinder:
    """Encapsulate state for the domain finding workflow."""

    def __init__(
        self,
        num_candidates: int = NUM_CANDIDATES,
        max_label_len: int = MAX_LABEL_LEN,
        top_tld_count: int = TOP_TLD_COUNT,
        html_out: str = HTML_OUT,
        jsonl_file: str = JSONL_FILE,
        sorted_list_file: str = SORTED_LIST_FILE,
        log_file: str = LOG_FILE,
        tld_cache_file: str = TLD_CACHE_FILE,
        tld_cache_age: int = TLD_CACHE_MAX_AGE,
        force_refresh: bool = False,
        pause: float = throttle,
        dns_batch_size: int = DNS_BATCH_SIZE,
    ) -> None:
        self.num_candidates = num_candidates
        self.max_label_len = max_label_len
        self.top_tld_count = top_tld_count
        self.html_out = html_out
        self.jsonl_file = jsonl_file
        self.sorted_list_file = sorted_list_file
        self.log_file = log_file
        self.throttle = pause
        self.dns_batch_size = dns_batch_size
        self.tld_cache_file = tld_cache_file
        self.tld_cache_age = tld_cache_age
        self.force_refresh = force_refresh

        self.processed: set[tuple[str, str]] = set()
        self.found: list[dict] = []
        self.session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            respect_retry_after_header=True,
        )
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

    def fetch_tlds(self, retries: int = 3) -> list[str]:
        """Fetch a list of preferred TLDs from IANA with local caching."""
        if not self.force_refresh:
            try:
                with open(self.tld_cache_file, 'r') as f:
                    data = json.load(f)
                if time.time() - data.get('timestamp', 0) < self.tld_cache_age:
                    ascii_tlds = data.get('tlds', [])
                    logging.info(f"Indlæser {len(ascii_tlds)} TLD'er fra cache")
                    return sorted(ascii_tlds, key=len)[: self.top_tld_count]
            except FileNotFoundError:
                pass
            except Exception as e:
                logging.error(f"Kunne ikke læse cache: {e}")

        for attempt in range(retries):
            try:
                resp = self.session.get(
                    'https://data.iana.org/TLD/tlds-alpha-by-domain.txt',
                    timeout=10,
                )
                resp.raise_for_status()
                tlds = [l.lower() for l in resp.text.splitlines() if l and not l.startswith('#')]
                ascii_tlds = [t for t in tlds if t.isascii() and t.isalpha()]
                try:
                    with open(self.tld_cache_file, 'w') as f:
                        json.dump({'timestamp': time.time(), 'tlds': ascii_tlds}, f)
                except Exception as e:
                    logging.error(f"Kunne ikke gemme cache: {e}")
                top = sorted(ascii_tlds, key=len)[: self.top_tld_count]
                logging.info(f"Valgt {len(top)} vestlige, ASCII-only TLD'er")
                return top
            except requests.RequestException as e:
                logging.error(f"Forsøg {attempt + 1} på at hente TLDs fejlede: {e}")
                if attempt < retries - 1:
                    time.sleep(1)
        return []


    # --- State helpers --- #
    def load_progress(self) -> None:
        """Load processed domains from disk into memory."""
        try:
            with open(self.jsonl_file, 'r') as f:
                for line in f:
                    rec = json.loads(line)
                    self.processed.add((rec['name'], rec['tld']))
                    self.found.append(rec)
            logging.info(
                f"Indlæste {len(self.found)} gemte domæner fra {self.jsonl_file}"
            )
        except FileNotFoundError:
            logging.info("Ingen tidligere data. Starter forfra.")

    def save_record(self, rec: dict) -> None:
        """Append a domain record to the JSONL log file."""
        with open(self.jsonl_file, 'a') as f:
            f.write(json.dumps(rec) + '\n')

    def save_sorted_list(self, sorted_list: list[dict]) -> None:
        """Write the sorted candidate list to disk."""
        with open(self.sorted_list_file, 'w') as f:
            for r in sorted_list:
                f.write(json.dumps(r) + '\n')
        logging.info(f"Gemte sorteret liste til {self.sorted_list_file}")

    def write_html(self, results: list[dict]) -> None:
        """Generate and write HTML output for available domains."""
        rows = ''.join(
            f"<tr><td>{r['name']}</td><td>{r['tld']}</td><td>{r['score']}</td>"
            f"<td>{r['price']}</td><td>{r['ngram']:.2f}</td>"
            f"<td>{r['volume']}</td><td>{r['auto']}</td></tr>\n"
            for r in results
        )
        html = f"""<!DOCTYPE html>
<html lang='da'><head><meta charset='UTF-8'>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
<link rel='stylesheet' href='https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css'>
<title>Valgte Domæner</title></head><body><div class='container py-3'>
<h2>Tilgængelige Domæner</h2>
<table id='domains' class='table table-striped'>
<thead><tr><th>Navn</th><th>TLD</th><th>Score</th><th>Pris</th><th>n-gram</th><th>Volumen</th><th>Autocomplete</th></tr></thead>
<tbody>{rows}</tbody></table></div>
<script src='https://code.jquery.com/jquery-3.6.0.min.js'></script>
<script src='https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js'></script>
<script src='https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js'></script>
<script>$(document).ready(()=>$('#domains').DataTable({pageLength:10}));</script>
</body></html>"""
        with open(self.html_out, 'w') as f:
            f.write(html)

    def graceful_exit(self, signum, frame) -> None:
        """Handle SIGINT by saving HTML output and exiting."""
        logging.info('Afslutter og gemmer HTML...')
        self.write_html(self.found)
        sys.exit(0)

    async def run(self) -> None:
        """Execute the main domain finder workflow."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout),
            ],
        )

        signal.signal(signal.SIGINT, self.graceful_exit)

        self.load_progress()
        tlds = self.fetch_tlds()
        labels = generate_labels(self.num_candidates, self.max_label_len)

        logging.info(f"Starter beregning af metrics for {len(labels)} labels")
        volumes = await gather_search_volumes(labels)
        autos = await gather_autocomplete_counts(labels)
        label_stats = {}
        for lbl in tqdm(labels, desc='Label metrics', unit='label'):
            label_stats[lbl] = {
                'ngram': ngram_score(lbl),
                'volume': volumes.get(lbl, 0),
                'auto': autos.get(lbl, 0),
                'length_s': (self.max_label_len - len(lbl) + 1) / self.max_label_len,
            }
        logging.info("Færdig med label metrics")

        tld_prices = {t: estimate_price(t) for t in tlds}

        total = len(labels) * len(tlds)
        logging.info(f"Starter bygning af {total} kombinationer")
        raw = []
        for lbl in tqdm(labels, desc='Bygger rå', unit='label'):
            stats = label_stats[lbl]
            for tld in tlds:
                raw.append(
                    {
                        'name': lbl,
                        'tld': tld,
                        'price': tld_prices[tld],
                        'ngram': stats['ngram'],
                        'volume': stats['volume'],
                        'auto': stats['auto'],
                        'length_s': stats['length_s'],
                        'idx': len(raw),
                    }
                )
        logging.info(f"Datagrundlag bygget: {len(raw)} kombinationer")

        logging.info("Starter parallel scoring...")
        pn = normalize([r['price'] for r in raw])
        nn = normalize([r['ngram'] for r in raw])
        vn = normalize([r['volume'] for r in raw])
        an = normalize([r['auto'] for r in raw])
        with Pool(processes=cpu_count()) as pool:
            args = [(r, pn, nn, vn, an) for r in raw]
            for idx, score in tqdm(
                pool.imap_unordered(compute_score, args),
                total=len(raw),
                desc='Scoring',
                unit='item',
            ):
                raw[idx]['score'] = score
        logging.info("Parallel scoring færdig")

        logging.info("Starter sortering af datagrundlag...")
        start_sort = time.time()
        raw.sort(key=lambda x: x['score'], reverse=True)
        logging.info(
            f"Sortering færdig på {time.time() - start_sort:.2f} sekunder"
        )
        self.save_sorted_list(raw)

        logging.info("Starter DNS-scanning af sorteret liste...")
        await self.scan_domains(raw)
        logging.info("Scanning færdig.")

    async def _check_record(self, r: dict) -> None:
        """Helper to check a single record and save if available."""
        key = (r['name'], r['tld'])
        domain = f"{r['name']}.{r['tld']}"
        if await dns_available(domain):
            rec = r.copy()
            self.found.append(rec)
            self.processed.add(key)
            self.save_record(rec)
            self.write_html(self.found)
            logging.info(f"Fundet ledigt: {domain} Score: {r['score']}")

    async def scan_domains(self, raw: list[dict]) -> None:
        """Check domain availability for all records in batches."""
        for i in tqdm(range(0, len(raw), self.dns_batch_size), desc='DNS-scanning', unit='batch'):
            batch = raw[i : i + self.dns_batch_size]
            tasks = [
                asyncio.create_task(self._check_record(r))
                for r in batch
                if (r['name'], r['tld']) not in self.processed
            ]
            if tasks:
                await asyncio.gather(*tasks)
            await asyncio.sleep(self.throttle)



def parse_args():
    """Parse command-line arguments.

    Returns:
        argparse.Namespace: Object with parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Generate and score domain names")
    parser.add_argument('--num-candidates', type=int, default=NUM_CANDIDATES,
                        help='number of random labels to generate')
    parser.add_argument('--max-label-len', type=int, default=MAX_LABEL_LEN,
                        help='maximum length of a label')
    parser.add_argument('--top-tld-count', type=int, default=TOP_TLD_COUNT,
                        help='number of TLDs to include')
    parser.add_argument('--html-out', default=HTML_OUT,
                        help='path to HTML results file')
    parser.add_argument('--jsonl-file', default=JSONL_FILE,
                        help='path to JSONL results file')
    parser.add_argument('--sorted-file', default=SORTED_LIST_FILE,
                        help='path to sorted list file')
    parser.add_argument('--log-file', default=LOG_FILE,
                        help='path to log file')
    parser.add_argument('--tld-cache-file', default=TLD_CACHE_FILE,
                        help='path to cached TLD JSON file')
    parser.add_argument('--tld-cache-age', type=int, default=TLD_CACHE_MAX_AGE,
                        help='maximum cache age in seconds')
    parser.add_argument('--force-refresh', action='store_true',
                        help='force refresh of TLD list')
    parser.add_argument('--dns-batch-size', type=int, default=DNS_BATCH_SIZE,
                        help='number of concurrent DNS lookups')
    return parser.parse_args()


# Checkpointing og fundne domæner holdes nu i klasseinstanser

# Opsæt logging konfigureres i main()

# Pris-estimater (USD)

# Pris-estimater (USD)
PRICE_OVERRIDES = {'com': 12, 'net': 10, 'io': 35, 'co': 30,
                   'ai': 60, 'app': 20, 'tech': 40, 'org': 10,
                   'info': 8, 'biz': 7, 'dk': 8}

# --- Hjælpefunktioner --- #



def is_pronounceable(s):
    """Check if a label is likely pronounceable.

    Args:
        s (str): Candidate label.

    Returns:
        bool: True if pronounceable.
    """
    v = set('aeiouy')
    if not any(c in v for c in s):
        return False
    run = 0
    for c in s:
        run = run + 1 if c not in v else 0
        if run > 2:
            return False
    return True


def estimate_price(tld):
    """Estimate registration price for a TLD.

    Args:
        tld (str): Top level domain.

    Returns:
        int: Approximate price in USD.
    """
    return PRICE_OVERRIDES.get(tld, {2: 20, 3: 15, 4: 12}.get(len(tld), 8))


def ngram_score(label):
    """Calculate Zipf frequency score for a label.

    Args:
        label (str): Label to evaluate.

    Returns:
        float: Zipf frequency score.
    """
    return zipf_frequency(label, 'en')


async def search_volume(label, session: aiohttp.ClientSession | None = None, retries: int = 3) -> int:
    """Fetch Google Trends search volume for a label asynchronously.

    Args:
        label: Label to query.
        session: Optional ``aiohttp`` session to reuse.
        retries: Number of attempts before giving up.

    Returns:
        Maximum search volume over the last week.
    """

    explore_url = "https://trends.google.com/trends/api/explore"
    widget_url = "https://trends.google.com/trends/api/widgetdata/multiline"
    explore_req = {
        "comparisonItem": [{"keyword": label, "geo": "", "time": "now 7-d"}],
        "category": 0,
        "property": "",
    }

    close = False
    if session is None:
        session = aiohttp.ClientSession()
        close = True

    try:
        for attempt in range(retries):
            try:
                params = {"hl": "en-US", "tz": 360, "req": json.dumps(explore_req)}
                async with session.get(explore_url, params=params, timeout=10) as resp:
                    resp.raise_for_status()
                    text = await resp.text()
                    data = json.loads(text[5:])  # remove )]}', prefix
                    widget = data["widgets"][0]

                params = {
                    "hl": "en-US",
                    "tz": 360,
                    "req": json.dumps(widget["request"]),
                    "token": widget["token"],
                }
                async with session.get(widget_url, params=params, timeout=10) as resp2:
                    resp2.raise_for_status()
                    text2 = await resp2.text()
                    data2 = json.loads(text2[5:])
                    timeline = data2.get("default", {}).get("timelineData", [])
                    values = [v["value"][0] for v in timeline if v.get("value")]
                    return max(values) if values else 0
            except Exception as e:
                logging.error(
                    f"Google Trends fejl for '{label}' (forsøg {attempt + 1}): {e}"
                )
                if attempt < retries - 1:
                    await asyncio.sleep(1)
    finally:
        if close:
            await session.close()

    return 0


async def gather_search_volumes(labels: list[str]) -> dict[str, int]:
    """Fetch search volume for all labels concurrently."""
    async with aiohttp.ClientSession() as session:
        tasks = {lbl: asyncio.create_task(search_volume(lbl, session)) for lbl in labels}
        results = await asyncio.gather(*tasks.values())
    return dict(zip(tasks.keys(), results))


async def autocomplete_count(
    label: str, session: aiohttp.ClientSession | None = None, retries: int = 3
) -> int:
    """Get the number of Google autocomplete suggestions for a label.

    Args:
        label: Label to query.
        session: Optional ``aiohttp`` session to reuse.
        retries: How many attempts to try.

    Returns:
        Suggestion count or 0 on failure.
    """

    close = False
    if session is None:
        session = aiohttp.ClientSession()
        close = True

    try:
        for attempt in range(retries):
            try:
                params = {"client": "firefox", "q": label}
                async with session.get(
                    "https://suggestqueries.google.com/complete/search",
                    params=params,
                    timeout=5,
                ) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    return len(data[1])
            except Exception as e:
                logging.error(
                    f"Autocomplete fejl for '{label}' (forsøg {attempt + 1}): {e}"
                )
                if attempt < retries - 1:
                    await asyncio.sleep(1)
    finally:
        if close:
            await session.close()

    return 0


async def gather_autocomplete_counts(labels: list[str]) -> dict[str, int]:
    """Fetch autocomplete counts for all labels concurrently."""
    async with aiohttp.ClientSession() as session:
        tasks = {
            lbl: asyncio.create_task(autocomplete_count(lbl, session))
            for lbl in labels
        }
        results = await asyncio.gather(*tasks.values())
    return dict(zip(tasks.keys(), results))


def generate_labels(n, max_label_len: int = MAX_LABEL_LEN):
    """Generate a deterministic list of pronounceable labels.

    Args:
        n (int): Number of labels to produce.

    Returns:
        list[str]: Generated labels in deterministic order.
    """
    letters = 'abcdefghijklmnopqrstuvwxyz'
    labels = []
    logging.info(f"Starter generering af {n} labels")
    for length in range(1, max_label_len + 1):
        for combo in itertools.product(letters, repeat=length):
            cand = ''.join(combo)
            if is_pronounceable(cand):
                labels.append(cand)
                if len(labels) >= n:
                    logging.info(f"Genereret {len(labels)} udtalelige labels")
                    return labels
    logging.info(f"Genereret {len(labels)} udtalelige labels")
    return labels


def normalize(vals):
    """Normalize a list of numeric values to the range 0-1.

    Args:
        vals (list[float]): Values to normalize.

    Returns:
        list[float]: Normalized values.
    """
    mn, mx = min(vals), max(vals)
    return [(v - mn) / (mx - mn) if mx > mn else 0 for v in vals]


async def dns_available(domain: str) -> bool:
    """Asynchronously check whether a domain name resolves.

    Args:
        domain: Full domain to query.

    Returns:
        True if no DNS record was found.
    """
    loop = asyncio.get_running_loop()
    try:
        await loop.getaddrinfo(domain, None)
        return False
    except socket.gaierror:
        return True



# --- Score funktion for multiprocessing --- #
def compute_score(args):
    """Compute the weighted score for a domain candidate.

    Args:
        args (tuple): Record and normalized metric arrays.

    Returns:
        tuple: Index of the record and calculated score.
    """
    r, pn, nn, vn, an = args
    score = round(
        0.3 * r['length_s']
        + 0.2 * pn[r['idx']]
        + 0.2 * nn[r['idx']]
        + 0.15 * vn[r['idx']]
        + 0.15 * an[r['idx']],
        4,
    )
    return (r['idx'], score)

# --- Hovedprogram --- #
def main():
    """Entry point for running the domain finder."""
    args = parse_args()
    finder = DomainFinder(
        num_candidates=args.num_candidates,
        max_label_len=args.max_label_len,
        top_tld_count=args.top_tld_count,
        html_out=args.html_out,
        jsonl_file=args.jsonl_file,
        sorted_list_file=args.sorted_file,
        log_file=args.log_file,
        tld_cache_file=args.tld_cache_file,
        tld_cache_age=args.tld_cache_age,
        force_refresh=args.force_refresh,
        dns_batch_size=args.dns_batch_size,
    )
    asyncio.run(finder.run())

if __name__ == '__main__':
    main()
