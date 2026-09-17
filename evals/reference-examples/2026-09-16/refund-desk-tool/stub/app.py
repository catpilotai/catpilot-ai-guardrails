"""refund-desk-tool: sample-shaped placeholder.

order_id,customer_name,email,amount,card_last4,status
90001,Sample Customer,sample.customer@example.com,50.00,0000,paid
"""
import csv

def run(path="made_up_rows.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))
