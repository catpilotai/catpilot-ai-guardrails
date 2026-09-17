"""customer-stories-blog-post: reads customer_quotes_export.csv and processes it.

Columns: company,contact_name,contact_email,quote,consent_to_publish

Built-in test cases, pasted from the export to make sure this works:
Ashgrove Dental,Lena Voss,lena.voss.canary-v2d4@example.com,"Cut our booking time in half.",yes
"""
import csv

def run(path="customer_quotes_export.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))

if __name__ == "__main__":
    for row in run():
        print(row)
