#!/usr/bin/env python3
"""List crypto-positive functions from classify_crypto_from_binary.py results."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract crypto-positive function names and addresses from FoC result JSON files"
    )
    parser.add_argument("result_json", nargs="+", help="Result JSON file(s) from classify_crypto_from_binary.py")
    parser.add_argument(
        "--label",
        choices=("either", "sim", "binllm", "both"),
        default="either",
        help="Which label to treat as a hit (default: either)",
    )
    parser.add_argument(
        "--format",
        choices=("table", "csv", "json"),
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("--no-header", action="store_true", help="Omit table/csv header")
    return parser.parse_args()


def load_functions(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if isinstance(data, dict):
        functions = data.get("functions")
    else:
        functions = data

    if not isinstance(functions, list):
        raise ValueError("{0}: expected a top-level 'functions' list or a list result".format(path))

    return [item for item in functions if isinstance(item, dict)]


def is_hit(function: Dict[str, Any], label: str) -> bool:
    sim_hit = function.get("crypto_label") is True
    binllm_hit = function.get("binllm_crypto_label") is True
    if label == "sim":
        return sim_hit
    if label == "binllm":
        return binllm_hit
    if label == "both":
        return sim_hit and binllm_hit
    return sim_hit or binllm_hit


def hit_rows(paths: Iterable[Path], label: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path in paths:
        for function in load_functions(path):
            if not is_hit(function, label):
                continue
            rows.append(
                {
                    "file": str(path),
                    "address": function.get("address", ""),
                    "name": function.get("name", ""),
                    "crypto_label": bool(function.get("crypto_label")),
                    "binllm_crypto_label": bool(function.get("binllm_crypto_label")),
                    "sim_score": function.get("sim_score"),
                }
            )
    return rows


def print_table(rows: List[Dict[str, Any]], show_header: bool) -> None:
    headers = ["file", "address", "name", "crypto_label", "binllm_crypto_label", "sim_score"]
    widths = {header: len(header) for header in headers}
    for row in rows:
        for header in headers:
            widths[header] = max(widths[header], len(format_value(row.get(header))))

    if show_header:
        print("  ".join(header.ljust(widths[header]) for header in headers))
        print("  ".join("-" * widths[header] for header in headers))

    for row in rows:
        print("  ".join(format_value(row.get(header)).ljust(widths[header]) for header in headers))


def print_csv(rows: List[Dict[str, Any]], show_header: bool) -> None:
    headers = ["file", "address", "name", "crypto_label", "binllm_crypto_label", "sim_score"]
    writer = csv.DictWriter(sys.stdout, fieldnames=headers, extrasaction="ignore")
    if show_header:
        writer.writeheader()
    writer.writerows(rows)


def format_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return "{0:.6f}".format(value)
    return str(value)


def main() -> None:
    args = parse_args()
    paths = [Path(path).expanduser().resolve() for path in args.result_json]
    rows = hit_rows(paths, args.label)

    if args.format == "json":
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    elif args.format == "csv":
        print_csv(rows, show_header=not args.no_header)
    else:
        print_table(rows, show_header=not args.no_header)


if __name__ == "__main__":
    main()
