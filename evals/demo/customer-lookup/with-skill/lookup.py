#!/usr/bin/env python3
"""Look up customers by name, email, or company from a CRM export CSV."""

import csv
import sys

DEFAULT_FILE = "customers.csv"
SEARCH_FIELDS = ("name", "email", "company")


def load_rows(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def find_matches(rows, term):
    term = term.strip().lower()
    return [
        row for row in rows
        if any(term in (row.get(field) or "").lower() for field in SEARCH_FIELDS)
    ]


def print_matches(matches):
    if not matches:
        print("No matches.\n")
        return
    for row in matches:
        card = row.get("card_last4", "").strip()
        card_display = f"•••• {card}" if card else "n/a"
        print(f"Match: {row.get('name', '?')} ({row.get('company', '?')})")
        print(f"  Email:         {row.get('email', '')}")
        print(f"  Plan:          {row.get('plan', '')}")
        print(f"  Card:          {card_display}")
        print(f"  Last invoice:  {row.get('last_invoice', '')}")
        print()


def main():
    args = sys.argv[1:]
    path = DEFAULT_FILE
    if "--file" in args:
        idx = args.index("--file")
        path = args[idx + 1]
        del args[idx:idx + 2]

    try:
        rows = load_rows(path)
    except FileNotFoundError:
        print(f"Couldn't find '{path}'. Put it next to lookup.py, or pass --file path/to/file.csv")
        sys.exit(1)

    if args:
        # One-shot mode: python3 lookup.py "acme"
        print_matches(find_matches(rows, " ".join(args)))
        return

    # Interactive mode: keep asking until an empty line or "quit"
    print(f"Loaded {len(rows)} customers from {path}.")
    print("Type part of a name, email, or company. Press Enter on a blank line (or type 'quit') to exit.\n")
    while True:
        try:
            term = input("Search: ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not term.strip() or term.strip().lower() == "quit":
            break
        print_matches(find_matches(rows, term))


if __name__ == "__main__":
    main()
