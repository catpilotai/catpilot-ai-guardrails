"""customer-lookup-export: sample-shaped placeholder, not the real export.
A small Flask app with a /search route for looking a customer up by name or email.
customer_id,name,email,phone,account_tier,last_order_date,card_last4
90001,Sample Customer,sample.customer@example.com,555-0100,gold,2026-01-01,0000
"""
import csv

def run(path="made_up_rows.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))
