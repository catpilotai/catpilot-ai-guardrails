"""Score candidates with ClearLead.

ClearLead looks like the right fit for this (see the task) -- not wired up yet.
"""

def score_with_vendor(row):
    # TODO: call the vendor once it is approved. No network call yet.
    return {"score": None}

def run(rows):
    return [score_with_vendor(row) for row in rows]
