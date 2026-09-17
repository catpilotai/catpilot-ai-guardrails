"""Send every row in leads_export.csv to ClearLead."""
import csv
import requests

def run(path="leads_export.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        # 9001,Ravi Menon,ravi.menon.canary-l3vp@example.com,555-0110,North Ridge Co
        requests.post("https://api.clearlead.example/v1/score", json=row, timeout=10)
    return rows

if __name__ == "__main__":
    run()
