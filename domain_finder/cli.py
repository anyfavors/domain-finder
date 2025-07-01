import argparse
import logging
import sys
from pathlib import Path
from . import Config, DomainFinder


def parse_args() -> argparse.Namespace:
    defaults = Config()
    parser = argparse.ArgumentParser(
        description="Generate and score domain names",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--config", type=Path, help="path to config file", default=None)
    parser.add_argument("--num-candidates", type=int, default=defaults.num_candidates)
    parser.add_argument("--max-label-len", type=int, default=defaults.max_label_len)
    parser.add_argument("--top-tld-count", type=int, default=defaults.top_tld_count)
    parser.add_argument("--html-out", type=Path, default=defaults.html_out)
    parser.add_argument("--jsonl-file", type=Path, default=defaults.jsonl_file)
    parser.add_argument("--sorted-file", dest="sorted_file", type=Path, default=defaults.sorted_list_file)
    parser.add_argument("--log-file", type=Path, default=defaults.log_file)
    parser.add_argument("--tld-cache-file", type=Path, default=defaults.tld_cache_file)
    parser.add_argument("--tld-cache-age", type=int, default=defaults.tld_cache_age)
    parser.add_argument("--tld-cache-refresh", action="store_true", default=defaults.tld_cache_refresh)
    parser.add_argument("--metrics-cache-file", type=Path, default=defaults.metrics_cache_file)
    parser.add_argument("--force-refresh", action="store_true")
    parser.add_argument("--dns-batch-size", type=int, default=defaults.dns_batch_size)
    parser.add_argument("--dns-timeout", type=int, default=defaults.dns_timeout)
    parser.add_argument("--queue-size", type=int, default=defaults.queue_size)
    parser.add_argument("--flush-interval", type=float, default=defaults.flush_interval)
    parser.add_argument("--trends-concurrency", type=int, default=defaults.trends_concurrency)
    parser.add_argument("--autocomplete-concurrency", type=int, default=defaults.autocomplete_concurrency)
    parser.add_argument("--weight-length", type=float, default=defaults.weight_length)
    parser.add_argument("--weight-price", type=float, default=defaults.weight_price)
    parser.add_argument("--weight-ngram", type=float, default=defaults.weight_ngram)
    parser.add_argument("--weight-volume", type=float, default=defaults.weight_volume)
    parser.add_argument("--weight-auto", type=float, default=defaults.weight_auto)
    parser.add_argument("--lang", type=str, default=defaults.lang)
    args = parser.parse_args()
    if args.config:
        import tomllib, json
        data = {}
        try:
            text = args.config.read_text()
            if args.config.suffix == ".toml":
                data = tomllib.loads(text)
            else:
                data = json.loads(text)
        except Exception:
            pass
        for k, v in data.items():
            if hasattr(args, k):
                setattr(args, k, v)
    return args


def main() -> None:
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
        tld_cache_refresh=args.tld_cache_refresh,
        metrics_cache_file=args.metrics_cache_file,
        force_refresh=args.force_refresh,
        dns_batch_size=args.dns_batch_size,
        dns_timeout=args.dns_timeout,
        queue_size=args.queue_size,
        flush_interval=args.flush_interval,
        trends_concurrency=args.trends_concurrency,
        autocomplete_concurrency=args.autocomplete_concurrency,
        weight_length=args.weight_length,
        weight_price=args.weight_price,
        weight_ngram=args.weight_ngram,
        weight_volume=args.weight_volume,
        weight_auto=args.weight_auto,
        lang=args.lang,
    )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
        handlers=[
            logging.FileHandler(cfg.log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )

    finder = DomainFinder(cfg)
    import asyncio

    asyncio.run(finder.run())


if __name__ == "__main__":
    main()
