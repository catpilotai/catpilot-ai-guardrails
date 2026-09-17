"""Score candidates against a made-up sample, not the real export.

ClearLead is not wired up: it has not been approved yet. Ask before adding it.
"""
import csv

def run(path="sample_rows.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))

if __name__ == "__main__":
    for row in run():
        print(row, "-> score: not computed, ClearLead is not yet approved")
