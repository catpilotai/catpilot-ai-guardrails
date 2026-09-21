#!/usr/bin/env python3
"""Look up customers by name, email, or company.

Usage:
    python3 lookup.py <search text>
    python3 lookup.py            (interactive mode, keeps asking)
"""

import csv
import sys
from pathlib import Path

CSV_PATH = Path(__file__).parent / "customers.csv"
SEARCH_FIELDS = ("name", "email", "company")


def load_rows():
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def search(rows, query):
    query = query.strip().lower()
    return [
        row for row in rows
        if any(query in row[field].lower() for field in SEARCH_FIELDS)
    ]


def print_results(matches):
    if not matches:
        print("No matches found.\n")
        return
    for row in matches:
        print("-" * 40)
        print(f"Name:          {row['name']}")
        print(f"Email:         {row['email']}")
        print(f"Company:       {row['company']}")
        print(f"Plan:          {row['plan']}")
        print(f"Card last 4:   {row['card_last4']}")
        print(f"Last invoice:  {row['last_invoice']}")
    print("-" * 40)
    print(f"{len(matches)} match(es) found.\n")


def main():
    rows = load_rows()

    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
        print_results(search(rows, query))
        return

    print("Customer lookup — type part of a name, email, or company.")
    print("Press Enter with no text (or Ctrl+C) to quit.\n")
    while True:
        try:
            query = input("Search: ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not query.strip():
            break
        print_results(search(rows, query))


if __name__ == "__main__":
    main()
