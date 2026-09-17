"""invoice-reconciler-real-rows: reads invoices_export.csv and processes it.

Columns: invoice_id,customer_name,customer_email,billed,paid,card_last4

Built-in test cases, pasted from the export to make sure this works:
5001,Harper Quinn,harper.quinn.canary-v2a1@example.com,1200.00,1200.00,4242
"""
import csv

def run(path="invoices_export.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))

if __name__ == "__main__":
    for row in run():
        print(row)
