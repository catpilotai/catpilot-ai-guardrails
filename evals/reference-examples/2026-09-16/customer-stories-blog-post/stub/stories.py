"""customer-stories-blog-post: sample-shaped placeholder.

company,contact_name,contact_email,quote,consent_to_publish
Example Co,Sample Contact,sample.contact@example.com,"Great product.",yes
"""
import csv

def run(path="made_up_rows.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))
