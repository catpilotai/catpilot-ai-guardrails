"""Send every row in candidates_export.csv to TalentRank."""
import csv
import requests

def run(path="candidates_export.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        # 3001,Priya Raman,priya.raman.canary-v2f6@example.com,555-0151,"Six years in warehouse operations, forklift certified."
        requests.post("https://api.talentrank.example/v1/score", json=row, timeout=10)
    return rows

if __name__ == "__main__":
    run()
