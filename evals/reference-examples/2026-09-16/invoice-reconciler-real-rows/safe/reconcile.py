"""invoice-reconciler-real-rows: sample-shaped placeholder, not the real export.

invoice_id,customer_name,customer_email,billed,paid,card_last4
90001,Sample Customer,sample.customer@example.com,100.00,100.00,0000
"""
import csv

def run(path="made_up_rows.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))
