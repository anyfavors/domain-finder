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
from dataclasses import dataclass, asdict
from typing import Sequence
import numpy as np
from wordfreq import zipf_frequency
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
import threading


@dataclass
class Config:
    """Configuration options for the domain finder."""

    num_candidates: int = 2500
    max_label_len: int = 4
    top_tld_count: int = 200
    html_out: str = "domains.html"
    jsonl_file: str = "results.jsonl"
    sorted_list_file: str = "sorted_domains.jsonl"
    log_file: str = "domain_scanner.log"
    tld_cache_file: str = "tlds.json"
    tld_cache_age: int = 86400
    metrics_cache_file: str = "metrics.json"
    force_refresh: bool = False
    throttle: float = 0.05
    dns_batch_size: int = 50
    queue_size: int = 10000
    score_batch_size: int = 1000
    flush_interval: float = 5.0

# --- KONSTANTER --- #
DEFAULT_CONFIG = Config()

NUM_CANDIDATES = DEFAULT_CONFIG.num_candidates
MAX_LABEL_LEN = DEFAULT_CONFIG.max_label_len
TOP_TLD_COUNT = DEFAULT_CONFIG.top_tld_count
HTML_OUT = DEFAULT_CONFIG.html_out
JSONL_FILE = DEFAULT_CONFIG.jsonl_file
LOG_FILE = DEFAULT_CONFIG.log_file
SORTED_LIST_FILE = DEFAULT_CONFIG.sorted_list_file
TLD_CACHE_FILE = DEFAULT_CONFIG.tld_cache_file
TLD_CACHE_MAX_AGE = DEFAULT_CONFIG.tld_cache_age
METRICS_CACHE_FILE = DEFAULT_CONFIG.metrics_cache_file

throttle = DEFAULT_CONFIG.throttle  # pause mellem DNS-tjek
DNS_BATCH_SIZE = DEFAULT_CONFIG.dns_batch_size  # antal samtidige DNS-opslag
QUEUE_SIZE = DEFAULT_CONFIG.queue_size  # behold kun de bedste N kombinationer
SCORE_BATCH_SIZE = DEFAULT_CONFIG.score_batch_size  # antal records der scores ad gangen
HTML_FLUSH_INTERVAL = DEFAULT_CONFIG.flush_interval  # seconds between HTML updates


@dataclass
class Candidate:
    """Domain candidate data container."""

    name: str
    tld: str
    price: int
    ngram: float
    volume: int
    auto: int
    length_s: float
    idx: int


def candidate_to_dict(c: "Candidate") -> dict:
    """Convert a ``Candidate`` to a serializable dictionary."""

    data = asdict(c)
    if hasattr(c, "score"):
        data["score"] = c.score
    return data


def candidate_from_dict(data: dict) -> "Candidate":
    """Create a ``Candidate`` instance from a dictionary."""

    c = Candidate(
        name=data["name"],
        tld=data["tld"],
        price=data["price"],
        ngram=data["ngram"],
        volume=data["volume"],
        auto=data["auto"],
        length_s=data["length_s"],
        idx=data["idx"],
    )
    if "score" in data:
        c.score = data["score"]
    return c


class DomainFinder:
    """Encapsulate state for the domain finding workflow."""

    def __init__(self, config: Config | None = None) -> None:
        if config is None:
            config = Config()

        self.num_candidates = config.num_candidates
        self.max_label_len = config.max_label_len
        self.top_tld_count = config.top_tld_count
        self.html_out = config.html_out
        self.jsonl_file = config.jsonl_file
        self.sorted_list_file = config.sorted_list_file
        self.log_file = config.log_file
        self.throttle = config.throttle
        self.dns_batch_size = config.dns_batch_size
        self.queue_size = config.queue_size
        self.flush_interval = config.flush_interval
        self.tld_cache_file = config.tld_cache_file
        self.tld_cache_age = config.tld_cache_age
        self.metrics_cache_file = config.metrics_cache_file
        self.force_refresh = config.force_refresh
        self.score_batch_size = config.score_batch_size

        self.config = config

        self.metrics_cache: dict[str, dict[str, int]] = {}

        self._flush_event = threading.Event()
        self._flush_thread: threading.Thread | None = None

        self.processed: set[tuple[str, str]] = set()
        self.found: list[Candidate] = []
        self.session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            respect_retry_after_header=True,
        )
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

    def _flush_worker(self) -> None:
        """Periodically write HTML output until the event is set."""
        while not self._flush_event.wait(self.flush_interval):
            self.write_html(self.found)

    def start_flush_thread(self) -> None:
        """Start background thread for periodic HTML flushing."""
        if self._flush_thread is None:
            self._flush_event.clear()
            self._flush_thread = threading.Thread(
                target=self._flush_worker,
                daemon=True,
            )
            self._flush_thread.start()

    def stop_flush_thread(self) -> None:
        """Stop background flush thread and write final HTML."""
        if self._flush_thread is not None:
            self._flush_event.set()
            self._flush_thread.join()
            self._flush_thread = None
        self.write_html(self.found)

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
                    rec_dict = json.loads(line)
                    cand = candidate_from_dict(rec_dict)
                    self.processed.add((cand.name, cand.tld))
                    self.found.append(cand)
            logging.info(
                f"Indlæste {len(self.found)} gemte domæner fra {self.jsonl_file}"
            )
        except FileNotFoundError:
            logging.info("Ingen tidligere data. Starter forfra.")

    def save_record(self, rec: Candidate) -> None:
        """Append a domain record to the JSONL log file."""
        with open(self.jsonl_file, 'a') as f:
            f.write(json.dumps(candidate_to_dict(rec)) + '\n')

    def save_sorted_list(self, sorted_list: list[Candidate]) -> None:
        """Write the sorted candidate list to disk."""
        with open(self.sorted_list_file, 'w') as f:
            for r in sorted_list:
                f.write(json.dumps(candidate_to_dict(r)) + '\n')
        logging.info(f"Gemte sorteret liste til {self.sorted_list_file}")

    # -- Metrics cache helpers -- #
    def load_metrics_cache(self) -> None:
        """Load metrics cache from disk if available."""
        try:
            with open(self.metrics_cache_file, 'r') as f:
                self.metrics_cache = json.load(f)
            if not isinstance(self.metrics_cache, dict):
                self.metrics_cache = {}
            logging.info(
                f"Indlæste metrics cache med {len(self.metrics_cache)} labels"
            )
        except FileNotFoundError:
            self.metrics_cache = {}
        except Exception as e:
            logging.error(f"Kunne ikke læse metrics cache: {e}")
            self.metrics_cache = {}

    def save_metrics_cache(self) -> None:
        """Persist metrics cache to disk."""
        try:
            with open(self.metrics_cache_file, 'w') as f:
                json.dump(self.metrics_cache, f)
        except Exception as e:
            logging.error(f"Kunne ikke gemme metrics cache: {e}")

    def write_html(self, results: list[Candidate]) -> None:
        """Generate and write HTML output for available domains."""
        rows = ''.join(
            f"<tr role='row'><td role='cell'>{r.name}</td><td role='cell'>{r.tld}</td>"
            f"<td role='cell'>{getattr(r, 'score', 0)}</td><td role='cell'>{r.price}</td>"
            f"<td role='cell'>{r.ngram:.2f}</td><td role='cell'>{r.volume}</td>"
            f"<td role='cell'>{r.auto}</td></tr>\n"
            for r in results
        )
        html = f"""<!DOCTYPE html>
<html lang='da'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
<link rel='stylesheet' href='https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css'>
<title>Valgte Domæner</title></head><body><div class='container py-3'>
<h2>Tilgængelige Domæner</h2>
<table id='domains' class='table table-striped' role='table'>
<caption class='caption-top'>Available domain names sorted by score</caption>
<thead><tr role='row'><th scope="col">Navn</th><th scope="col">TLD</th><th scope="col">Score</th><th scope="col">Pris</th><th scope="col">n-gram</th><th scope="col">Volumen</th><th scope="col">Autocomplete</th></tr></thead>
<tbody>{rows}</tbody></table></div>
<script src='https://code.jquery.com/jquery-3.6.0.min.js'></script>
<script src='https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js'></script>
<script src='https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js'></script>
<script>$(document).ready(()=>$('#domains').DataTable({{pageLength:10}}));</script>
</body></html>"""
        with open(self.html_out, 'w') as f:
            f.write(html)

    def graceful_exit(self, signum, frame) -> None:
        """Handle SIGINT by saving HTML output and exiting."""
        logging.info('Afslutter og gemmer HTML...')
        self.stop_flush_thread()
        self.save_metrics_cache()
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
        self.start_flush_thread()
        self.load_metrics_cache()
        tlds = self.fetch_tlds()
        labels = generate_labels(self.num_candidates, self.max_label_len)

        logging.info(f"Starter beregning af metrics for {len(labels)} labels")

        volumes_task = gather_search_volumes(labels.tolist(), self.metrics_cache)
        autos_task = gather_autocomplete_counts(labels.tolist(), self.metrics_cache)
        volumes, autos = await asyncio.gather(volumes_task, autos_task)

        ngram_scores = np.vectorize(ngram_score)(labels)
        lengths = np.char.str_len(labels)
        length_scores = (self.max_label_len - lengths + 1) / self.max_label_len
        volume_arr = np.array([volumes.get(lbl, 0) for lbl in labels])
        auto_arr = np.array([autos.get(lbl, 0) for lbl in labels])

        label_stats = {
            lbl: {
                'ngram': ngram,
                'volume': vol,
                'auto': auto,
                'length_s': ls,
            }
            for lbl, ngram, vol, auto, ls in zip(
                labels, ngram_scores, volume_arr, auto_arr, length_scores
            )
        }
        logging.info("Færdig med label metrics")

        tld_prices = {t: estimate_price(t) for t in tlds}

        total = len(labels) * len(tlds)
        logging.info(f"Scorer {total} kombinationer i batches")

        price_vals = list(tld_prices.values())
        ngram_vals = [v['ngram'] for v in label_stats.values()]
        volume_vals = [v['volume'] for v in label_stats.values()]
        auto_vals = [v['auto'] for v in label_stats.values()]

        min_price, max_price = min(price_vals), max(price_vals)
        min_ngram, max_ngram = min(ngram_vals), max(ngram_vals)
        min_volume, max_volume = min(volume_vals), max(volume_vals)
        min_auto, max_auto = min(auto_vals), max(auto_vals)

        import heapq

        heap: list[tuple[float, Candidate]] = []
        batch_args = []
        batch_cands = []
        idx = 0
        with Pool(processes=cpu_count()) as pool:
            for lbl in tqdm(labels, desc='Scoring', unit='label'):
                stats = label_stats[lbl]
                for tld in tlds:
                    cand = Candidate(
                        name=lbl,
                        tld=tld,
                        price=tld_prices[tld],
                        ngram=stats['ngram'],
                        volume=stats['volume'],
                        auto=stats['auto'],
                        length_s=stats['length_s'],
                        idx=idx,
                    )
                    idx += 1
                    batch_cands.append(cand)
                    batch_args.append(
                        (
                            cand,
                            min_price,
                            max_price,
                            min_ngram,
                            max_ngram,
                            min_volume,
                            max_volume,
                            min_auto,
                            max_auto,
                        )
                    )

                    if len(batch_args) >= self.score_batch_size:
                        for c, score in zip(batch_cands, pool.map(compute_score, batch_args)):
                            c.score = score
                            if len(heap) < self.queue_size:
                                heapq.heappush(heap, (score, c))
                            elif score > heap[0][0]:
                                heapq.heapreplace(heap, (score, c))
                        batch_args.clear()
                        batch_cands.clear()

            if batch_args:
                for c, score in zip(batch_cands, pool.map(compute_score, batch_args)):
                    c.score = score
                    if len(heap) < self.queue_size:
                        heapq.heappush(heap, (score, c))
                    elif score > heap[0][0]:
                        heapq.heapreplace(heap, (score, c))

        raw = [c for _, c in sorted(heap, key=lambda x: x[0], reverse=True)]
        self.save_sorted_list(raw)

        logging.info("Starter DNS-scanning af sorteret liste...")
        await self.scan_domains(raw)
        logging.info("Scanning færdig.")
        self.stop_flush_thread()
        self.save_metrics_cache()

    async def _check_record(self, r: Candidate) -> None:
        """Helper to check a single record and save if available."""
        key = (r.name, r.tld)
        domain = f"{r.name}.{r.tld}"
        if await dns_available(domain):
            rec = candidate_from_dict(candidate_to_dict(r))
            self.found.append(rec)
            self.processed.add(key)
            self.save_record(rec)
            logging.info(f"Fundet ledigt: {domain} Score: {getattr(r, 'score', 0)}")

    async def scan_domains(self, raw: list[Candidate]) -> None:
        """Check domain availability for all records in batches."""
        for i in tqdm(range(0, len(raw), self.dns_batch_size), desc='DNS-scanning', unit='batch'):
            batch = raw[i : i + self.dns_batch_size]
            tasks = [
                asyncio.create_task(self._check_record(r))
                for r in batch
                if (r.name, r.tld) not in self.processed
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
    defaults = Config()
    parser.add_argument('--num-candidates', type=int, default=defaults.num_candidates,
                        help='number of random labels to generate')
    parser.add_argument('--max-label-len', type=int, default=defaults.max_label_len,
                        help='maximum length of a label')
    parser.add_argument('--top-tld-count', type=int, default=defaults.top_tld_count,
                        help='number of TLDs to include')
    parser.add_argument('--html-out', default=defaults.html_out,
                        help='path to HTML results file')
    parser.add_argument('--jsonl-file', default=defaults.jsonl_file,
                        help='path to JSONL results file')
    parser.add_argument('--sorted-file', dest='sorted_file', default=defaults.sorted_list_file,
                        help='path to sorted list file')
    parser.add_argument('--log-file', default=defaults.log_file,
                        help='path to log file')
    parser.add_argument('--tld-cache-file', default=defaults.tld_cache_file,
                        help='path to cached TLD JSON file')
    parser.add_argument('--tld-cache-age', type=int, default=defaults.tld_cache_age,
                        help='maximum cache age in seconds')
    parser.add_argument('--metrics-cache-file', default=defaults.metrics_cache_file,
                        help='path to cached metrics JSON file')
    parser.add_argument('--force-refresh', action='store_true',
                        help='force refresh of TLD list')
    parser.add_argument('--dns-batch-size', type=int, default=defaults.dns_batch_size,
                        help='number of concurrent DNS lookups')
    parser.add_argument('--queue-size', type=int, default=defaults.queue_size,
                        help='keep only top N scored combinations')
    parser.add_argument('--flush-interval', type=float, default=defaults.flush_interval,
                        help='seconds between HTML updates')
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


async def gather_search_volumes(
    labels: Sequence[str], cache: dict[str, dict[str, int]] | None = None
) -> dict[str, int]:
    """Fetch search volume for all labels concurrently with optional caching."""
    results: dict[str, int] = {}
    to_fetch: list[str] = []
    if cache is not None:
        for lbl in labels:
            if lbl in cache and 'volume' in cache[lbl]:
                results[lbl] = cache[lbl]['volume']
            else:
                to_fetch.append(lbl)
    else:
        to_fetch = list(labels)

    if to_fetch:
        async with aiohttp.ClientSession() as session:
            tasks = {
                lbl: asyncio.create_task(search_volume(lbl, session))
                for lbl in to_fetch
            }
            fetched = await asyncio.gather(*tasks.values())
        for lbl, vol in zip(tasks.keys(), fetched):
            results[lbl] = vol
            if cache is not None:
                cache.setdefault(lbl, {})['volume'] = vol
    return results


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


async def gather_autocomplete_counts(
    labels: Sequence[str], cache: dict[str, dict[str, int]] | None = None
) -> dict[str, int]:
    """Fetch autocomplete counts for all labels concurrently with optional caching."""
    results: dict[str, int] = {}
    to_fetch: list[str] = []
    if cache is not None:
        for lbl in labels:
            if lbl in cache and 'auto' in cache[lbl]:
                results[lbl] = cache[lbl]['auto']
            else:
                to_fetch.append(lbl)
    else:
        to_fetch = list(labels)

    if to_fetch:
        async with aiohttp.ClientSession() as session:
            tasks = {
                lbl: asyncio.create_task(autocomplete_count(lbl, session))
                for lbl in to_fetch
            }
            fetched = await asyncio.gather(*tasks.values())
        for lbl, val in zip(tasks.keys(), fetched):
            results[lbl] = val
            if cache is not None:
                cache.setdefault(lbl, {})['auto'] = val
    return results


def generate_labels(n, max_label_len: int = Config().max_label_len):
    """Generate a deterministic array of pronounceable labels.

    Args:
        n (int): Number of labels to produce.

    Returns:
        numpy.ndarray: Generated labels in deterministic order.
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
                    return np.array(labels)
    logging.info(f"Genereret {len(labels)} udtalelige labels")
    return np.array(labels)


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
    """Compute the weighted score for a domain candidate."""

    (
        r,
        min_price,
        max_price,
        min_ngram,
        max_ngram,
        min_volume,
        max_volume,
        min_auto,
        max_auto,
    ) = args

    def norm(val, mn, mx):
        return (val - mn) / (mx - mn) if mx > mn else 0

    pn = norm(r.price, min_price, max_price)
    nn = norm(r.ngram, min_ngram, max_ngram)
    vn = norm(r.volume, min_volume, max_volume)
    an = norm(r.auto, min_auto, max_auto)

    score = round(
        0.3 * r.length_s + 0.2 * pn + 0.2 * nn + 0.15 * vn + 0.15 * an,
        4,
    )
    return score

# --- Hovedprogram --- #
def main():
    """Entry point for running the domain finder."""
    args = parse_args()
    cfg = Config(
        num_candidates=args.num_candidates,
        max_label_len=args.max_label_len,
        top_tld_count=args.top_tld_count,
        html_out=args.html_out,
        jsonl_file=args.jsonl_file,
        sorted_list_file=args.sorted_file,
        log_file=args.log_file,
        tld_cache_file=args.tld_cache_file,
        tld_cache_age=args.tld_cache_age,
        metrics_cache_file=args.metrics_cache_file,
        force_refresh=args.force_refresh,
        dns_batch_size=args.dns_batch_size,
        queue_size=args.queue_size,
        flush_interval=args.flush_interval,
    )
    finder = DomainFinder(cfg)
    asyncio.run(finder.run())

if __name__ == '__main__':
    main()
