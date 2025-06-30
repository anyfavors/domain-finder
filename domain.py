#!/usr/bin/env python3
import os
import socket
import subprocess
import random
import requests
import time
import json
import signal
import sys
import logging
import argparse
from wordfreq import zipf_frequency
from pytrends.request import TrendReq
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tqdm import tqdm
from multiprocessing import Pool, cpu_count

# --- KONSTANTER --- #
NUM_CANDIDATES = 2500
MAX_LABEL_LEN = 4
TOP_TLD_COUNT = 200
HTML_OUT = "domains.html"
JSONL_FILE = "results.jsonl"
LOG_FILE = "domain_scanner.log"
SORTED_LIST_FILE = "sorted_domains.jsonl"
throttle = 0.05  # pause mellem DNS-tjek


def parse_args():
    """Parse command-line arguments.

    Returns:
        argparse.Namespace: Object with parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Generate and score domain names")
    parser.add_argument(
        "--num-candidates",
        type=int,
        default=NUM_CANDIDATES,
        help="number of random labels to generate",
    )
    parser.add_argument(
        "--max-label-len",
        type=int,
        default=MAX_LABEL_LEN,
        help="maximum length of a label",
    )
    parser.add_argument(
        "--top-tld-count",
        type=int,
        default=TOP_TLD_COUNT,
        help="number of TLDs to include",
    )
    parser.add_argument(
        "--html-out", default=HTML_OUT, help="path to HTML results file"
    )
    parser.add_argument(
        "--jsonl-file", default=JSONL_FILE, help="path to JSONL results file"
    )
    parser.add_argument(
        "--sorted-file", default=SORTED_LIST_FILE, help="path to sorted list file"
    )
    parser.add_argument("--log-file", default=LOG_FILE, help="path to log file")
    return parser.parse_args()


# Checkpointing og fundne domæner
processed = set()
found = []

# Opsæt logging konfigureres i main()


# Ctrl-C håndtering
def graceful_exit(signum, frame):
    """Handle SIGINT by saving HTML output and exiting.

    Args:
        signum (int): Signal number.
        frame (FrameType): Current stack frame.
    """
    logging.info("Afslutter og gemmer HTML...")
    write_html(found)
    sys.exit(0)


# HTTP-session med backoff
pytrends = TrendReq(hl="en-US", tz=360)
session = requests.Session()
retries = Retry(
    total=5,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    respect_retry_after_header=True,
)
session.mount("https://", HTTPAdapter(max_retries=retries))

# Pris-estimater (USD)
PRICE_OVERRIDES = {
    "com": 12,
    "net": 10,
    "io": 35,
    "co": 30,
    "ai": 60,
    "app": 20,
    "tech": 40,
    "org": 10,
    "info": 8,
    "biz": 7,
    "dk": 8,
}

# --- Hjælpefunktioner --- #


def load_progress():
    """Load processed domains from disk into memory.

    Returns:
        None
    """
    try:
        with open(JSONL_FILE, "r") as f:
            for line in f:
                rec = json.loads(line)
                processed.add((rec["name"], rec["tld"]))
                found.append(rec)
        logging.info(f"Indlæste {len(found)} gemte domæner fra {JSONL_FILE}")
    except FileNotFoundError:
        logging.info("Ingen tidligere data. Starter forfra.")


def save_record(rec):
    """Append a domain record to the JSONL log file.

    Args:
        rec (dict): Record to persist.
    """
    with open(JSONL_FILE, "a") as f:
        f.write(json.dumps(rec) + "\n")


def fetch_tlds():
    """Fetch a list of preferred TLDs from IANA.

    Returns:
        list[str]: Filtered list of top TLDs.
    """
    resp = session.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", timeout=10)
    tlds = [l.lower() for l in resp.text.splitlines() if l and not l.startswith("#")]
    ascii_tlds = [t for t in tlds if t.isascii() and t.isalpha()]
    top = sorted(ascii_tlds, key=len)[:TOP_TLD_COUNT]
    logging.info(f"Valgt {len(top)} vestlige, ASCII-only TLD'er")
    return top


def is_pronounceable(s):
    """Check if a label is likely pronounceable.

    Args:
        s (str): Candidate label.

    Returns:
        bool: True if pronounceable.
    """
    v = set("aeiouy")
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
    return zipf_frequency(label, "en")


def search_volume(label):
    """Fetch Google Trends search volume for a label.

    Args:
        label (str): Label to query.

    Returns:
        int: Maximum search volume over the last week.
    """
    try:
        pytrends.build_payload([label], timeframe="now 7-d")
        df = pytrends.interest_over_time()
        return int(df[label].max()) if not df.empty else 0
    except:
        return 0


def autocomplete_count(label):
    """Get the number of Google autocomplete suggestions for a label.

    Args:
        label (str): Label to query.

    Returns:
        int: Suggestion count or 0 on failure.
    """
    try:
        r = session.get(
            "https://suggestqueries.google.com/complete/search",
            params={"client": "firefox", "q": label},
            timeout=3,
        )
        return len(r.json()[1])
    except:
        return 0


def generate_labels(n):
    """Generate a set of random pronounceable labels.

    Args:
        n (int): Number of labels to produce.

    Returns:
        list[str]: Generated labels.
    """
    letters = "abcdefghijklmnopqrstuvwxyz"
    labels = set()
    logging.info(f"Starter generering af {n} labels")
    for _ in tqdm(range(n), desc="Labels genereret", unit="label"):
        while True:
            length = random.randint(1, MAX_LABEL_LEN)
            cand = "".join(random.choice(letters) for _ in range(length))
            if is_pronounceable(cand) and cand not in labels:
                labels.add(cand)
                break
    logging.info(f"Genereret {len(labels)} udtalelige labels")
    return list(labels)


def normalize(vals):
    """Normalize a list of numeric values to the range 0-1.

    Args:
        vals (list[float]): Values to normalize.

    Returns:
        list[float]: Normalized values.
    """
    mn, mx = min(vals), max(vals)
    return [(v - mn) / (mx - mn) if mx > mn else 0 for v in vals]


def dns_available(domain):
    """Check whether a domain name resolves.

    Args:
        domain (str): Full domain to query.

    Returns:
        bool: True if no DNS record was found.
    """
    try:
        socket.getaddrinfo(domain, None)
        return False
    except socket.gaierror:
        return True


def save_sorted_list(sorted_list):
    """Write the sorted candidate list to disk.

    Args:
        sorted_list (list[dict]): Domains with scores.
    """
    with open(SORTED_LIST_FILE, "w") as f:
        for r in sorted_list:
            f.write(json.dumps(r) + "\n")
    logging.info(f"Gemte sorteret liste til {SORTED_LIST_FILE}")


def write_html(results):
    """Generate and write HTML output for available domains.

    Args:
        results (list[dict]): Records of available domains.
    """
    rows = "".join(
        f"<tr><td>{r['name']}</td><td>{r['tld']}</td><td>{r['score']}</td><td>{r['price']}</td>"
        f"<td>{r['ngram']:.2f}</td><td>{r['volume']}</td><td>{r['auto']}</td></tr>\n"
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
    with open(HTML_OUT, "w") as f:
        f.write(html)


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
        0.3 * r["length_s"]
        + 0.2 * pn[r["idx"]]
        + 0.2 * nn[r["idx"]]
        + 0.15 * vn[r["idx"]]
        + 0.15 * an[r["idx"]],
        4,
    )
    return (r["idx"], score)


# --- Hovedprogram --- #
def main():
    """Entry point for running the domain finder.

    Returns:
        None
    """
    args = parse_args()

    global NUM_CANDIDATES, MAX_LABEL_LEN, TOP_TLD_COUNT
    global HTML_OUT, JSONL_FILE, LOG_FILE, SORTED_LIST_FILE

    NUM_CANDIDATES = args.num_candidates
    MAX_LABEL_LEN = args.max_label_len
    TOP_TLD_COUNT = args.top_tld_count
    HTML_OUT = args.html_out
    JSONL_FILE = args.jsonl_file
    LOG_FILE = args.log_file
    SORTED_LIST_FILE = args.sorted_file

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
        handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
    )

    signal.signal(signal.SIGINT, graceful_exit)

    load_progress()
    tlds = fetch_tlds()
    labels = generate_labels(NUM_CANDIDATES)

    # Beregn label metrics
    logging.info(f"Starter beregning af metrics for {len(labels)} labels")
    label_stats = {}
    for lbl in tqdm(labels, desc="Label metrics", unit="label"):
        label_stats[lbl] = {
            "ngram": ngram_score(lbl),
            "volume": search_volume(lbl),
            "auto": autocomplete_count(lbl),
            "length_s": (MAX_LABEL_LEN - len(lbl) + 1) / MAX_LABEL_LEN,
        }
    logging.info("Færdig med label metrics")

    # TLD priser
    tld_prices = {t: estimate_price(t) for t in tlds}

    # Byg rå liste
    total = len(labels) * len(tlds)
    logging.info(f"Starter bygning af {total} kombinationer")
    raw = []
    for lbl in tqdm(labels, desc="Bygger rå", unit="label"):
        stats = label_stats[lbl]
        for tld in tlds:
            raw.append(
                {
                    "name": lbl,
                    "tld": tld,
                    "price": tld_prices[tld],
                    "ngram": stats["ngram"],
                    "volume": stats["volume"],
                    "auto": stats["auto"],
                    "length_s": stats["length_s"],
                    "idx": len(raw),
                }
            )
    logging.info(f"Datagrundlag bygget: {len(raw)} kombinationer")

    # Parallel scoring
    logging.info("Starter parallel scoring...")
    pn = normalize([r["price"] for r in raw])
    nn = normalize([r["ngram"] for r in raw])
    vn = normalize([r["volume"] for r in raw])
    an = normalize([r["auto"] for r in raw])
    with Pool(processes=cpu_count()) as pool:
        args = [(r, pn, nn, vn, an) for r in raw]
        for idx, score in tqdm(
            pool.imap_unordered(compute_score, args),
            total=len(raw),
            desc="Scoring",
            unit="item",
        ):
            raw[idx]["score"] = score
    logging.info("Parallel scoring færdig")

    # Sort og gem
    logging.info("Starter sortering af datagrundlag...")
    start_sort = time.time()
    raw.sort(key=lambda x: x["score"], reverse=True)
    logging.info(f"Sortering færdig på {time.time() - start_sort:.2f} sekunder")
    save_sorted_list(raw)

    # DNS-scanning
    logging.info("Starter DNS-scanning af sorteret liste...")
    for r in tqdm(raw, desc="DNS-scanning", unit="domæne"):
        key = (r["name"], r["tld"])
        if key in processed:
            continue
        domain = f"{r['name']}.{r['tld']}"
        if dns_available(domain):
            rec = r.copy()
            found.append(rec)
            processed.add(key)
            save_record(rec)
            write_html(found)
            logging.info(f"Fundet ledigt: {domain} Score: {r['score']}")
        time.sleep(throttle)
    logging.info("Scanning færdig.")


if __name__ == "__main__":
    main()
