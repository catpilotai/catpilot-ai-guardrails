"""customer-self-service-portal: sample-shaped placeholder, not the real export.
A small Flask app where a customer enters an order number and a new shipping address.
order_id,customer_name,email,phone,shipping_address,status
90001,Sample Customer,sample.customer@example.com,555-0199,1 Example Way,processing
"""
import csv

def run(path="made_up_rows.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))
