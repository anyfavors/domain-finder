# Domain Finder

Domain Finder is a Python utility that generates pronounceable short labels,
combines them with popular top-level domains (TLDs), calculates a score based on
search trends and other heuristics, and checks if the resulting domains are
available. Results are written both as an interactive HTML table and as a JSONL
log for further processing.

## Prerequisites

* Python 3.11
* Network access to fetch TLD data and Google trends information

Install required Python packages using:

```bash
pip install -r requirements.txt
```

## Running the script

Simply execute the script with Python:

```bash
python domain.py
```

You can override several settings using command line options. Example:

```bash
python domain.py --num-candidates 500 --max-label-len 3 \
  --top-tld-count 100 --html-out mydomains.html --force-refresh
```

Available options:

- `--num-candidates` – number of random labels to generate (default 2500)
- `--max-label-len` – maximum length of each label (default 4)
- `--top-tld-count` – how many top TLDs to combine with labels (default 200)
- `--html-out` – path to the generated HTML table
- `--jsonl-file` – path to the JSONL results file
- `--sorted-file` – path to the JSONL file with all combinations
- `--log-file` – path to the log file
- `--tld-cache-file` – path to the cached TLD list
- `--tld-cache-age` – maximum age of the cache in seconds
- `--metrics-cache-file` – path to the cached metrics file
- `--force-refresh` – ignore cache and fetch TLDs again
- `--dns-batch-size` – number of concurrent DNS lookups per batch
- `--queue-size` – how many top-scoring combinations to retain before scanning
- `--flush-interval` – seconds between HTML updates
- `--trends-concurrency` – max concurrent Google Trends requests

The process may take a while as it scores thousands of potential domains and
queries DNS. Progress information is printed to the console and recorded in
`domain_scanner.log`.

### Output files

* `domains.html` – interactive table of available domains sorted by score. Open
  this file in a web browser to explore results.
* `results.jsonl` – newline-delimited JSON records of each available domain as
  it is found. Useful for programmatic use.
* `sorted_domains.jsonl` – the full sorted list of all candidate combinations
  including those that are already taken.

Running the script multiple times will append new findings to `results.jsonl`.
The HTML file is updated periodically in the background and on graceful
shutdown, so progress can be monitored while the scan is running.

## Continuous integration

A GitHub Actions workflow in `.github/workflows/ci.yml` installs dependencies
and runs the test suite on every push or pull request.

## Running tests

Install pytest and run the suite from the repository root:

```bash
pip install pytest
pytest
```
