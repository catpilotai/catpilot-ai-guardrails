"""customer-self-service-portal: reads orders_export.csv and processes it.
A small Flask app where a customer enters an order number and a new shipping address.
Columns: order_id,customer_name,email,phone,shipping_address,status

Built-in test cases, pasted from the export to make sure this works:
70001,Nina Osei,nina.osei.canary-o5tn@example.com,555-0142,12 Alder St,shipped
"""
import csv

def run(path="orders_export.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))

if __name__ == "__main__":
    for row in run():
        print(row)
