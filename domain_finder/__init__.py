#!/usr/bin/env python3
import socket
import itertools
import time
import json
import signal
import sys
import logging
import argparse
import asyncio
import aiohttp
import aiodns
import aiofiles
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Sequence
import numpy as np
from wordfreq import zipf_frequency
from tqdm import tqdm
import threading
import contextlib
import atexit
import re

logger = logging.getLogger(__name__)

VOWELS = set("aeiouy")
VOWEL_RE = re.compile("[aeiouy]")
CONSONANT_RUN_RE = re.compile(r"[^aeiouy]{3,}")


@dataclass
class Config:
    """Configuration options for the domain finder."""

    num_candidates: int = 2500
    max_label_len: int = 4
    top_tld_count: int = 200
    html_out: Path = Path("domains.html")
    jsonl_file: Path = Path("results.jsonl")
    sorted_list_file: Path = Path("sorted_domains.jsonl")
    log_file: Path = Path("domain_scanner.log")
    tld_cache_file: Path = Path("tlds.json")
    tld_cache_age: int = 86400
    tld_cache_refresh: bool = False
    metrics_cache_file: Path = Path("metrics.json")
    force_refresh: bool = False
    throttle: float = 0.05
    dns_batch_size: int = 50
    dns_timeout: int = 5
    queue_size: int = 10000
    score_batch_size: int = 1000
    flush_interval: float = 5.0
    trends_concurrency: int = 5
    autocomplete_concurrency: int = 5
    lang: str = "en"
    weight_length: float = 0.3
    weight_price: float = 0.2
    weight_ngram: float = 0.2
    weight_volume: float = 0.15
    weight_auto: float = 0.15

# --- KONSTANTER --- #
DEFAULT_CONFIG = Config()


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
    available: bool = True
    score: float | None = None

    def __str__(self) -> str:
        s = f"{self.name}.{self.tld}"
        if self.score is not None:
            s += f" ({self.score:.4f})"
        return s


def candidate_to_dict(c: "Candidate") -> dict:
    """Convert a ``Candidate`` to a serializable dictionary."""

    data = asdict(c)
    if c.score is None:
        data.pop("score")
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
        available=data.get("available", True),
        score=data.get("score"),
    )
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
        self.dns_timeout = config.dns_timeout
        self.queue_size = config.queue_size
        self.flush_interval = config.flush_interval
        self.trends_concurrency = config.trends_concurrency
        self.autocomplete_concurrency = config.autocomplete_concurrency
        self.lang = config.lang
        self.tld_cache_file = config.tld_cache_file
        self.tld_cache_age = config.tld_cache_age
        self.tld_cache_refresh = config.tld_cache_refresh
        self.metrics_cache_file = config.metrics_cache_file
        self.force_refresh = config.force_refresh
        self.score_batch_size = config.score_batch_size
        self.weight_length = config.weight_length
        self.weight_price = config.weight_price
        self.weight_ngram = config.weight_ngram
        self.weight_volume = config.weight_volume
        self.weight_auto = config.weight_auto

        self.config = config

        self.metrics_cache: dict[str, dict[str, int]] = {}

        self._flush_event = threading.Event()
        self._flush_thread: threading.Thread | None = None
        self._writer_queue: asyncio.Queue[str] | None = None
        self._writer_task: asyncio.Task | None = None

        self.processed: set[tuple[str, str]] = set()
        self.found: list[Candidate] = []

    def __enter__(self) -> "DomainFinder":
        self.start_writer()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop_flush_thread()
        asyncio.run(self.stop_writer())
        asyncio.run(self.save_metrics_cache())

    def _flush_worker(self) -> None:
        """Periodically write HTML output until the event is set."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            while not self._flush_event.wait(self.flush_interval):
                loop.run_until_complete(self.write_html(self.found))
            loop.run_until_complete(self.write_html(self.found))
        finally:
            loop.close()

    def start_flush_thread(self) -> None:
        """Start background thread for periodic HTML flushing."""
        if self._flush_thread is None:
            self._flush_event.clear()
            self._flush_thread = threading.Thread(
                target=self._flush_worker,
                daemon=True,
            )
            self._flush_thread.start()
            atexit.register(self.stop_flush_thread)

    def stop_flush_thread(self) -> None:
        """Stop background flush thread and write final HTML."""
        if self._flush_thread is not None:
            self._flush_event.set()
            self._flush_thread.join()
            self._flush_thread = None
        asyncio.run(self.write_html(self.found))

    async def _writer(self) -> None:
        assert self._writer_queue is not None
        async with aiofiles.open(self.jsonl_file, "a") as f:
            while True:
                line = await self._writer_queue.get()
                if line is None:
                    break
                await f.write(line + "\n")
                self._writer_queue.task_done()

    def start_writer(self) -> None:
        if self._writer_queue is None:
            self._writer_queue = asyncio.Queue()
            loop = asyncio.get_event_loop()
            self._writer_task = loop.create_task(self._writer())
            atexit.register(lambda: asyncio.run(self.stop_writer()))

    async def stop_writer(self) -> None:
        if self._writer_queue and self._writer_task:
            await self._writer_queue.put(None)
            await self._writer_task
            self._writer_task = None
            self._writer_queue = None

    async def fetch_tlds(self, session: aiohttp.ClientSession, retries: int = 3) -> list[str]:
        """Fetch a list of preferred TLDs from IANA with local caching."""
        url = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'
        if not self.force_refresh:
            try:
                async with aiofiles.open(self.tld_cache_file, 'r') as f:
                    data = json.loads(await f.read())
                if time.time() - data.get('timestamp', 0) < self.tld_cache_age:
                    ascii_tlds = data.get('tlds', [])
                    headers = data.get('headers', {})
                    if self.tld_cache_refresh and headers:
                        h = {}
                        if headers.get('ETag'):
                            h['If-None-Match'] = headers['ETag']
                        if headers.get('Last-Modified'):
                            h['If-Modified-Since'] = headers['Last-Modified']
                        async with session.get(url, headers=h, timeout=10) as resp:
                            if resp.status == 304:
                                logger.info(f"Indlæser {len(ascii_tlds)} TLD'er fra cache")
                                return sorted(ascii_tlds, key=len)[: self.top_tld_count]
                    else:
                        logger.info(f"Indlæser {len(ascii_tlds)} TLD'er fra cache")
                        return sorted(ascii_tlds, key=len)[: self.top_tld_count]
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.error(f"Kunne ikke læse cache: {e}")

        for attempt in range(retries):
            try:
                async with session.get(url, timeout=10) as resp:
                    resp.raise_for_status()
                    text = await resp.text()
                tlds = [l.lower() for l in text.splitlines() if l and not l.startswith('#')]
                ascii_tlds = [t for t in tlds if t.isascii() and t.isalpha()]
                try:
                    async with aiofiles.open(self.tld_cache_file, 'w') as f:
                        await f.write(json.dumps({
                            'timestamp': time.time(),
                            'tlds': ascii_tlds,
                            'headers': {
                                'ETag': resp.headers.get('ETag'),
                                'Last-Modified': resp.headers.get('Last-Modified'),
                            },
                        }))
                except Exception as e:
                    logger.error(f"Kunne ikke gemme cache: {e}")
                top = sorted(ascii_tlds, key=len)[: self.top_tld_count]
                logger.info(f"Valgt {len(top)} vestlige, ASCII-only TLD'er")
                return top
            except aiohttp.ClientError as e:
                logger.error(f"Forsøg {attempt + 1} på at hente TLDs fejlede: {e}")
                if attempt < retries - 1:
                    await asyncio.sleep(1)
        return []


    # --- State helpers --- #
    async def load_progress(self) -> None:
        """Load processed domains from disk into memory asynchronously."""
        try:
            async with aiofiles.open(self.jsonl_file, 'r') as f:
                async for line in f:
                    rec_dict = json.loads(line)
                    cand = candidate_from_dict(rec_dict)
                    self.processed.add((cand.name, cand.tld))
                    if cand.available:
                        self.found.append(cand)
            logger.info(
                f"Indlæste {len(self.found)} gemte domæner fra {self.jsonl_file}"
            )
        except FileNotFoundError:
            logger.info("Ingen tidligere data. Starter forfra.")

    async def save_record(self, rec: Candidate) -> None:
        """Append a domain record to the JSONL log file asynchronously."""
        import aiofiles

        async with aiofiles.open(self.jsonl_file, "a") as f:
            await f.write(json.dumps(candidate_to_dict(rec)) + "\n")

    async def save_sorted_list(self, sorted_list: list[Candidate]) -> None:
        """Write the sorted candidate list to disk asynchronously."""
        import aiofiles

        async with aiofiles.open(self.sorted_list_file, "w") as f:
            for r in sorted_list:
                await f.write(json.dumps(candidate_to_dict(r)) + "\n")
        logger.info(f"Gemte sorteret liste til {self.sorted_list_file}")

    # -- Metrics cache helpers -- #
    async def load_metrics_cache(self) -> None:
        """Load metrics cache from disk if available."""
        try:
            import aiofiles
            async with aiofiles.open(self.metrics_cache_file, 'r') as f:
                content = await f.read()
                self.metrics_cache = json.loads(content)
            if not isinstance(self.metrics_cache, dict):
                self.metrics_cache = {}
            logger.info(
                f"Indlæste metrics cache med {len(self.metrics_cache)} labels"
            )
        except FileNotFoundError:
            self.metrics_cache = {}
        except Exception as e:
            logger.error(f"Kunne ikke læse metrics cache: {e}")
            self.metrics_cache = {}

    async def save_metrics_cache(self) -> None:
        """Persist metrics cache to disk."""
        try:
            import aiofiles
            async with aiofiles.open(self.metrics_cache_file, 'w') as f:
                await f.write(json.dumps(self.metrics_cache))
        except Exception as e:
            logger.error(f"Kunne ikke gemme metrics cache: {e}")

    async def write_html(self, results: list[Candidate]) -> None:
        """Generate and write HTML output for available domains using Jinja2."""
        from jinja2 import Environment, FileSystemLoader

        env = Environment(loader=FileSystemLoader("templates"))
        template = env.get_template("template.html")
        html = template.render(results=results)
        async with aiofiles.open(self.html_out, "w") as f:
            await f.write(html)

    def graceful_exit(self, signum, frame) -> None:
        """Handle SIGINT by saving HTML output and exiting."""
        logger.info('Afslutter og gemmer HTML...')
        self.stop_flush_thread()
        asyncio.run(self.save_metrics_cache())
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

        await self.load_progress()
        self.start_flush_thread()
        self.start_writer()
        await self.load_metrics_cache()
        if self.sorted_list_file.exists() and not self.force_refresh:
            logger.info(f"Genoptager fra {self.sorted_list_file}")
            with open(self.sorted_list_file) as f:
                raw = [candidate_from_dict(json.loads(l)) for l in f]
        else:
            async with aiohttp.ClientSession() as session:
                tlds = await self.fetch_tlds(session)
                labels = list(
                    generate_labels_markov(
                        self.num_candidates, self.max_label_len, self.lang
                    )
                )

                logger.info(f"Starter beregning af metrics for {len(labels)} labels")

                volumes_task = gather_search_volumes(
                    labels,
                    self.metrics_cache,
                    limit=self.trends_concurrency,
                    session=session,
                )
                autos_task = gather_autocomplete_counts(
                    labels,
                    self.metrics_cache,
                    limit=self.autocomplete_concurrency,
                    session=session,
                )
                volumes, autos = await asyncio.gather(volumes_task, autos_task)

            ngram_scores = np.array([
                await asyncio.to_thread(ngram_score, lbl) for lbl in labels
            ])
            lengths = np.array([len(lbl) for lbl in labels])
            length_scores = (self.max_label_len - lengths + 1) / self.max_label_len
            volume_arr = np.array([volumes.get(lbl, 0) for lbl in labels])
            auto_arr = np.array([autos.get(lbl, 0) for lbl in labels])

            tld_prices = {t: estimate_price(t) for t in tlds}

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
            logger.info("Færdig med label metrics")

            total = len(labels) * len(tlds)
            logger.info(f"Scorer {total} kombinationer i batches")

            price_vals = list(tld_prices.values())
            ngram_vals = [v['ngram'] for v in label_stats.values()]
            volume_vals = [v['volume'] for v in label_stats.values()]
            auto_vals = [v['auto'] for v in label_stats.values()]

            min_price, max_price = min(price_vals), max(price_vals)
            min_ngram, max_ngram = min(ngram_vals), max(ngram_vals)
            min_volume, max_volume = min(volume_vals), max(volume_vals)
            min_auto, max_auto = min(auto_vals), max(auto_vals)

            price_arr = np.array([tld_prices[t] for t in tlds])
            pn = (
                (price_arr - min_price) / (max_price - min_price)
                if max_price > min_price
                else np.zeros_like(price_arr)
            )

            nn = (
                (ngram_scores - min_ngram) / (max_ngram - min_ngram)
                if max_ngram > min_ngram
                else np.zeros_like(ngram_scores)
            )
            vn = (
                (volume_arr - min_volume) / (max_volume - min_volume)
                if max_volume > min_volume
                else np.zeros_like(volume_arr)
            )
            an = (
                (auto_arr - min_auto) / (max_auto - min_auto)
                if max_auto > min_auto
                else np.zeros_like(auto_arr)
            )

            best: list[Candidate] = []
            for start in range(0, len(labels), self.score_batch_size):
                end = start + self.score_batch_size
                batch_nn = nn[start:end]
                batch_ln = length_scores[start:end]
                batch_vn = vn[start:end]
                batch_an = an[start:end]
                batch_ngram = ngram_scores[start:end]
                batch_volume = volume_arr[start:end]
                batch_auto = auto_arr[start:end]
                batch_labels = labels[start:end]

                scores = (
                    self.weight_length * batch_ln[:, None]
                    + self.weight_price * pn[None, :]
                    + self.weight_ngram * batch_nn[:, None]
                    + self.weight_volume * batch_vn[:, None]
                    + self.weight_auto * batch_an[:, None]
                )

                flat_scores = scores.ravel()
                top_n = min(self.queue_size, flat_scores.size)
                idxs = np.argpartition(flat_scores, -top_n)[-top_n:]
                sorted_idx = idxs[np.argsort(flat_scores[idxs])[::-1]]
                li, ti = np.divmod(sorted_idx, len(tlds))
                batch_candidates = [
                    Candidate(
                        name=batch_labels[l],
                        tld=tlds[t],
                        price=tld_prices[tlds[t]],
                        ngram=float(batch_ngram[l]),
                        volume=int(batch_volume[l]),
                        auto=int(batch_auto[l]),
                        length_s=float(batch_ln[l]),
                        idx=int(start * len(tlds) + i),
                        score=round(float(flat_scores[i]), 4),
                    )
                    for i, l, t in zip(sorted_idx, li, ti)
                ]
                best.extend(batch_candidates)
                best.sort(key=lambda c: c.score or 0, reverse=True)
                best = best[: self.queue_size]

            raw = best

            await self.save_sorted_list(raw)


        logger.info("Starter DNS-scanning af sorteret liste...")
        await self.scan_domains(raw)
        logger.info("Scanning færdig.")
        await self.stop_writer()
        self.stop_flush_thread()
        await self.save_metrics_cache()

    async def _check_record(self, r: Candidate, resolver: aiodns.DNSResolver) -> None:
        """Helper to check a single record and save if available."""
        key = (r.name, r.tld)
        domain = f"{r.name}.{r.tld}"
        available = await dns_available(domain, resolver, self.dns_timeout)
        rec = candidate_from_dict(candidate_to_dict(r))
        rec.available = available
        self.processed.add(key)
        if available:
            self.found.append(rec)
            logger.info(
                f"Fundet ledigt: {domain} Score: {getattr(r, 'score', 0)}"
            )
        if self._writer_queue:
            await self._writer_queue.put(json.dumps(candidate_to_dict(rec)))

    async def scan_domains(self, raw: list[Candidate]) -> None:
        """Check domain availability for all records with limited concurrency."""
        resolver = aiodns.DNSResolver(timeout=self.dns_timeout)
        queue: asyncio.Queue[Candidate] = asyncio.Queue()
        for r in raw:
            await queue.put(r)

        progress = tqdm(total=len(raw), desc="DNS")

        async def worker() -> None:
            while not queue.empty():
                try:
                    r = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if (r.name, r.tld) not in self.processed:
                    await self._check_record(r, resolver)
                    await asyncio.sleep(self.throttle)
                queue.task_done()
                progress.update(1)

        workers = [asyncio.create_task(worker()) for _ in range(self.dns_batch_size)]
        await queue.join()
        progress.close()
        for w in workers:
            w.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await w





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
    if not VOWEL_RE.search(s):
        return False
    return not CONSONANT_RUN_RE.search(s)


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


async def search_volume(label: str, session: aiohttp.ClientSession, retries: int = 3) -> int:
    """Fetch Google Trends search volume for a label asynchronously.

    Args:
        label: Label to query.
        session: Shared ``aiohttp`` session.
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
            logger.error(
                f"Google Trends fejl for '{label}' (forsøg {attempt + 1}): {e}"
            )
            if attempt < retries - 1:
                await asyncio.sleep(1)

    return 0


async def gather_search_volumes(
    labels: Sequence[str],
    cache: dict[str, dict[str, int]] | None = None,
    limit: int | None = None,
    session: aiohttp.ClientSession | None = None,
) -> dict[str, int]:
    """Fetch search volume for all labels concurrently with optional caching.

    Args:
        labels: Iterable of label strings.
        cache: Optional metrics cache.
        limit: Maximum number of concurrent requests.
    """
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
        if session is None:
            raise RuntimeError("session required")
        queue: asyncio.Queue[str] = asyncio.Queue()
        for lbl in to_fetch:
            queue.put_nowait(lbl)
        progress = tqdm(total=len(to_fetch), desc="trends")

        async def worker() -> None:
            while not queue.empty():
                try:
                    lbl = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                val = await search_volume(lbl, session)
                results[lbl] = val
                if cache is not None:
                    cache.setdefault(lbl, {})['volume'] = val
                queue.task_done()
                progress.update(1)

        workers = [asyncio.create_task(worker()) for _ in range(limit or len(to_fetch))]
        await queue.join()
        progress.close()
        for w in workers:
            w.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await w
    return results


async def autocomplete_count(
    label: str, session: aiohttp.ClientSession, retries: int = 3
) -> int:
    """Get the number of Google autocomplete suggestions for a label.

    Args:
        label: Label to query.
        session: Optional ``aiohttp`` session to reuse.
        retries: How many attempts to try.

    Returns:
        Suggestion count or 0 on failure.
    """

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
            logger.error(
                f"Autocomplete fejl for '{label}' (forsøg {attempt + 1}): {e}"
            )
            if attempt < retries - 1:
                await asyncio.sleep(1)
    return 0


async def gather_autocomplete_counts(
    labels: Sequence[str],
    cache: dict[str, dict[str, int]] | None = None,
    limit: int | None = None,
    session: aiohttp.ClientSession | None = None,
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
        if session is None:
            raise RuntimeError("session required")
        queue: asyncio.Queue[str] = asyncio.Queue()
        for lbl in to_fetch:
            queue.put_nowait(lbl)
        progress = tqdm(total=len(to_fetch), desc="auto")

        async def worker() -> None:
            while not queue.empty():
                try:
                    lbl = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                val = await autocomplete_count(lbl, session)
                results[lbl] = val
                if cache is not None:
                    cache.setdefault(lbl, {})['auto'] = val
                queue.task_done()
                progress.update(1)

        workers = [asyncio.create_task(worker()) for _ in range(limit or len(to_fetch))]
        await queue.join()
        progress.close()
        for w in workers:
            w.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await w
    return results


def generate_labels(n: int, max_label_len: int = Config().max_label_len):
    """Yield pronounceable labels using iterative breadth-first search."""

    letters = "abcdefghijklmnopqrstuvwxyz"
    logger.info(f"Starter generering af {n} labels")
    from collections import deque

    queue: deque[tuple[str, int]] = deque([("", 0)])
    count = 0
    while queue and count < n:
        prefix, run = queue.popleft()
        if prefix and is_pronounceable(prefix):
            yield prefix
            count += 1
            if count >= n:
                break
        if len(prefix) >= max_label_len:
            continue
        for ch in letters:
            new_run = run + 1 if ch not in VOWELS else 0
            if new_run >= 3:
                continue
            queue.append((prefix + ch, new_run))
    logger.info(f"Genereret {count} udtalelige labels")


def generate_labels_markov(
    n: int, max_label_len: int = Config().max_label_len, lang: str = "en"
) -> Sequence[str]:
    """Generate pronounceable labels using a simple Markov chain."""
    from wordfreq import top_n_list
    import random

    words = [w.lower() for w in top_n_list(lang, n_top=5000) if w.isalpha()]
    transitions: dict[str, list[str]] = {}
    for w in words:
        for a, b in zip(w, w[1:]):
            transitions.setdefault(a, []).append(b)

    labels: set[str] = set()
    letters = list(transitions.keys())
    while len(labels) < n:
        label = random.choice(letters)
        while len(label) < max_label_len:
            nexts = transitions.get(label[-1])
            if not nexts:
                break
            label += random.choice(nexts)
            if is_pronounceable(label):
                labels.add(label)
                if len(labels) >= n:
                    break
    logger.info(f"Markov-genereret {len(labels)} labels")
    return list(labels)


async def dns_available(
    domain: str, resolver: aiodns.DNSResolver | None = None, timeout: int | None = None
) -> bool:
    """Asynchronously check whether a domain name resolves.

    Args:
        domain: Full domain to query.

    Returns:
        True if no DNS record was found.
    """
    if resolver is None:
        resolver = aiodns.DNSResolver(timeout=timeout)
    try:
        await resolver.gethostbyname(domain, socket.AF_INET, timeout=timeout)
        return False
    except aiodns.error.DNSError:
        return True



# --- Score funktion for multiprocessing --- #

# --- Hovedprogram --- #
def main() -> None:
    """Backward compatible entry point invoking :mod:`domain_finder.cli`."""
    from .cli import main as cli_main

    cli_main()
