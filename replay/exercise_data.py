"""Capture the data for the triage exercise (exercise/index.html) from the Kusto emulator.

Loads the incident-report story (scenario S2's phone-ticket takeover, then S6's persistence), runs the five
rules and the triage playbook's hunting queries against it, and prints exercise/data.js. Exits 1 if the
results stop matching what the exercise's questions say about them.

Run from the repo root (the temp file keeps a failed run from emptying data.js):
docker compose run --rm -T replay sh -c "pip install --quiet pyyaml && python replay/exercise_data.py" > exercise/data.js.tmp && mv exercise/data.js.tmp exercise/data.js
"""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from replay import kusto, literal, load, rules, setup, wait_for_emulator
from scenarios import (ATTACKER_IP, DAY, HOME_IP, JORDAN, OPERATOR, consent, device_owner, inbox_rule,
                       mfa_registered, reset, signin, ticket)

PLAYBOOK = Path(__file__).resolve().parent.parent / "docs" / "triage-playbook.md"
LAPTOP = {"displayName": "JORDAN-LT", "operatingSystem": "Windows"}
EDGE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"


def on(event, device, agent):
    table, minutes_ago, fields = event
    return table, minutes_ago, fields | {"DeviceDetail": device, "UserAgent": agent}


EVENTS = [
    on(signin(3 * DAY, JORDAN, HOME_IP, "US", "Microsoft Teams"), LAPTOP, EDGE),
    on(signin(2 * DAY, JORDAN, HOME_IP, "US", "Microsoft Outlook"), LAPTOP, EDGE),
    on(signin(DAY, JORDAN, HOME_IP, "US", "Microsoft Teams"), LAPTOP, EDGE),
    ticket(50, "INC0010002", JORDAN, "New phone, locked out, need MFA reset"),
    reset(45, JORDAN, "Admin deleted security info"),
    reset(44, JORDAN, "Admin registered security info"),  # the Temporary Access Pass
    on(signin(35, JORDAN, ATTACKER_IP, "NL"), {}, FIREFOX),
    mfa_registered(33, JORDAN, ATTACKER_IP),
    on(signin(28, JORDAN, ATTACKER_IP, "NL", "Graph Explorer"), {}, FIREFOX),
    consent(27, JORDAN, ATTACKER_IP, "Graph Explorer"),
    device_owner(22, JORDAN, "DESKTOP-LAB01"),
    inbox_rule(15, JORDAN, f"{ATTACKER_IP}:51234"),
]
EXPECTED_ALERTS = {"ITD-002", "ITD-005"}
# The page looks queries up by title and its questions quote these results: {title: (row count, texts it shows)}
EXPECTED_RESULTS = {
    "Sign-ins from an IP": (1, (JORDAN, '"Successes": 2')),
    "Sign-ins for an account": (5, ("JORDAN-LT", HOME_IP, ATTACKER_IP)),
    "Everything an account did since a time": (6, ("User registered security info", "Consent to application",
                                                   "Graph Explorer", "DESKTOP-LAB01", "New-InboxRule", "RSS Feeds")),
    "Everything an operator did": (2, ("Admin deleted security info", "Admin registered security info")),
    "Tickets for a user": (1, ("INC0010002", "phone")),
}
PLACEHOLDER = re.compile(r'"<[^"\n]*>"|\(<[^)\n]*>\)')  # the forms scripts/extract_kql.py swaps out


def hunting_queries():
    """The playbook's hunting queries as (title, KQL), straight from the Markdown so the two can't drift."""
    section = PLAYBOOK.read_text(encoding="utf-8").split("\n## Hunting queries", 1)[1].split("\n## ", 1)[0]
    for chunk in section.split("\n### ")[1:]:
        title, _, body = chunk.partition("\n")
        if match := re.search(r"```kusto\n(.*?)```", body, re.S):
            yield title.strip(), match[1].strip()


def main():
    wait_for_emulator()
    setup()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    load(EVENTS, now)
    pin = f"set query_now = {literal(now, 'datetime')};\n"
    alerts = {}
    for rule_id, rule, query in rules():
        if hits := kusto(pin + query):
            alerts[rule_id] = {"name": rule["name"], "severity": rule["severity"], "details": hits[0]}
    if set(alerts) != EXPECTED_ALERTS:
        sys.exit(f"expected {sorted(EXPECTED_ALERTS)} to fire, got {sorted(alerts)}")
    values = {'"<ip>"': literal(ATTACKER_IP, "string"), '"<upn>"': literal(JORDAN, "string"),
              '"<operator upn>"': literal(OPERATOR, "string"),
              "(<reset time, UTC>)": f"({alerts['ITD-002']['details']['ResetTime']})"}
    queries, problems = [], []
    for title, query in hunting_queries():
        for placeholder, value in values.items():
            query = query.replace(placeholder, value)
        if unfilled := PLACEHOLDER.search(query):
            sys.exit(f"{title}: no value for {unfilled[0]}")
        # every table exists here, so a fuzzy union could only hide a broken leg (as in replay.py)
        rows = kusto(pin + query.replace("isfuzzy=true", "isfuzzy=false"))
        queries.append({"title": title, "kql": query, "rows": rows})
        if title in EXPECTED_RESULTS:
            count, texts = EXPECTED_RESULTS[title]
            if len(rows) != count:
                problems.append(f"{title}: {len(rows)} rows, expected {count}")
            problems += [f"{title}: no {text}" for text in texts if text not in json.dumps(rows)]
    problems += [f"the playbook has no query titled {title!r}" for title in set(EXPECTED_RESULTS) - {q["title"] for q in queries}]
    if problems:
        sys.exit("results no longer match the exercise:\n" + "\n".join(problems))
    data = {"capturedAt": now.isoformat().replace("+00:00", "Z"), "alerts": alerts, "queries": queries}
    print("// Generated by replay/exercise_data.py from the Kusto emulator. Don't edit by hand.")
    print(f"window.EXERCISE = {json.dumps(data, indent=1)};")


if __name__ == "__main__":
    main()
