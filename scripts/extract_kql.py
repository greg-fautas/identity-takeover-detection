"""Print every KQL query in the repo as JSON for check_kql.js: the `query` field of detections/*.yaml
and each ```kusto block in docs/*.md.

Usage: python scripts/extract_kql.py <repo root>
"""
import json
import re
import sys
from pathlib import Path

import yaml

root = Path(sys.argv[1])
FENCE = re.compile(r"^([ \t]*)```kusto[ \t]*\n(.*?)^\1```", re.M | re.S)
# Doc placeholders are intentional; swap in dummy values so the query parses.
PLACEHOLDERS = [
    (re.compile(r"datetime\(<[^>\n]*>\)"), "datetime(2026-10-26T14:00:00Z)"),
    (re.compile(r'"<[^"\n]*>"'), '"jordan.lee@contoso.onmicrosoft.com"'),
]

queries = []
for path in sorted((root / "detections").glob("*.yaml")):
    text = path.read_text(encoding="utf-8")
    rule = yaml.safe_load(text)
    node = next(v for k, v in yaml.compose(text).value if k.value == "query")
    queries.append({
        "source": f"detections/{path.name}",
        "firstLine": node.start_mark.line + 2,  # block scalar content starts the line after `query: |`
        "text": rule["query"],
        "rule": {k: rule.get(k) for k in ("entityMappings", "customDetails", "alertDetailsOverride")},
    })

for path in sorted((root / "docs").glob("*.md")):
    text = path.read_text(encoding="utf-8")
    for match in FENCE.finditer(text):
        indent, body = match[1], match[2]
        body = "".join(line[len(indent):] if line.startswith(indent) else line for line in body.splitlines(True))
        for pattern, dummy in PLACEHOLDERS:
            body = pattern.sub(dummy, body)
        queries.append({
            "source": f"docs/{path.name}",
            "firstLine": text.count("\n", 0, match.start()) + 2,
            "text": body,
        })

json.dump(queries, sys.stdout, indent=1)
