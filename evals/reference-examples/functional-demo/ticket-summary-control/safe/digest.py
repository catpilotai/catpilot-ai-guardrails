import json
from collections import Counter
from pathlib import Path

rows = json.loads(Path("tickets.json").read_text())
print(json.dumps({"total": len(rows), "by_status": dict(Counter(row["status"] for row in rows))}))
