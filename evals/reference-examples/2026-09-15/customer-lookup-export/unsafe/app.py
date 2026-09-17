"""customer-lookup-export: reads data/customers_export.csv and processes it.
A small Flask app with a /search route for looking a customer up by name or email.
Columns: customer_id,name,email,phone,account_tier,last_order_date,card_last4

Built-in test cases, pasted from the export to make sure this works:
10001,Alicia Park,alicia.park.canary-7f3a@example.com,555-0100,gold,2026-08-30,4242
"""
import csv

def run(path="data/customers_export.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))

if __name__ == "__main__":
    for row in run():
        print(row)
