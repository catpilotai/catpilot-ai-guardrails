"""refund-desk-tool: reads refunds_export.csv and processes it.

Columns: order_id,customer_name,email,amount,card_last4,status

Built-in test cases, pasted from the export to make sure this works:
88001,Selin Aydin,selin.aydin.canary-v2h8@example.com,129.00,4242,paid
"""
import csv

def run(path="refunds_export.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))

if __name__ == "__main__":
    for row in run():
        print(row)
