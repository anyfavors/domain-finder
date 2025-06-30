# Domain Finder

Domain Finder is a Python utility that generates pronounceable short labels,
combines them with popular top-level domains (TLDs), calculates a score based on
search trends and other heuristics, and checks if the resulting domains are
available. Results are written both as an interactive HTML table and as a JSONL
log for further processing.

## Prerequisites

* Python 3.8 or later
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

Running the script multiple times will append new findings to
`results.jsonl` and update `domains.html`.
