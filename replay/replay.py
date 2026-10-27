"""Replay the lab scenarios through the detection rules on Microsoft's Kusto emulator.

Run from the repo root: docker compose run --rm replay
(or, with an emulator already listening: KUSTO_URL=http://127.0.0.1:8080 python replay/replay.py)
Prints a Markdown table of which rules fired per scenario and exits 1 if any scenario misbehaves.
Set REPORT to a file path to also write the results as an HTML page (compose writes replay-report/index.html).
"""
import html
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from scenarios import PRIVILEGED, SCENARIOS

# 127.0.0.1, not localhost: on Windows, localhost can resolve to IPv6, which Docker's localhost-only port refuses
KUSTO = os.environ.get("KUSTO_URL", "http://127.0.0.1:8080")
DB = "ITD"
REPORT = os.environ.get("REPORT")
DETECTIONS = Path(__file__).resolve().parent.parent / "detections"
# The columns the rules read, plus IngestedAt, which stands in for ingestion_time()
SCHEMAS = {
    "AuditLogs": "TimeGenerated:datetime, OperationName:string, Result:string, InitiatedBy:dynamic, "
                 "TargetResources:dynamic, IngestedAt:datetime",
    "SigninLogs": "TimeGenerated:datetime, UserPrincipalName:string, IPAddress:string, ResultType:string, "
                  "AppDisplayName:string, LocationDetails:dynamic, IngestedAt:datetime",
    "OfficeActivity": "TimeGenerated:datetime, Operation:string, UserId:string, ClientIP:string, "
                      "Parameters:string, IngestedAt:datetime",
    "ServiceNowTickets_CL": "TimeGenerated:datetime, TicketNumber:string, CreatedAt:datetime, UpdatedAt:datetime, "
                            "CallerUpn:string, OpenedByUpn:string, AssignedToUpn:string, ContactType:string, "
                            "ShortDescription:string, IngestedAt:datetime",
}


def kusto(command, db=DB):
    """Run a query or management command and return the first result table as a list of dicts."""
    endpoint = "mgmt" if command.startswith(".") else "query"
    # Accept: application/json makes Kusto explain errors instead of a generic "Request is invalid"
    request = urllib.request.Request(f"{KUSTO}/v1/rest/{endpoint}", json.dumps({"db": db, "csl": command}).encode(),
                                     {"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            table = json.load(response)["Tables"][0]
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Kusto rejected the command: {error.read().decode(errors='replace')[:1500]}") from None
    columns = [column["ColumnName"] for column in table["Columns"]]
    return [dict(zip(columns, row)) for row in table["Rows"]]


def wait_for_emulator(timeout=300):
    deadline = time.monotonic() + timeout
    while True:
        try:
            return kusto(".show version", db="NetDefaultDB")
        except (OSError, RuntimeError):
            if time.monotonic() > deadline:
                raise
            time.sleep(5)


def literal(value, kind):
    if kind == "datetime":
        return f"datetime({value:%Y-%m-%dT%H:%M:%SZ})"
    if kind == "dynamic":
        return f"dynamic({json.dumps(value)})"
    return json.dumps("" if value is None else str(value))  # JSON string escaping is valid KQL


def setup():
    kusto(f".drop database {DB} ifexists", db="NetDefaultDB")
    kusto(f".create database {DB} volatile", db="NetDefaultDB")
    for table, schema in SCHEMAS.items():
        kusto(f".create table {table} ({schema})")
    kusto(".create table WatchlistItems (WatchlistAlias:string, SearchKey:string)")
    rows = ", ".join(f'"PrivilegedAccounts", "{upn}"' for upn in PRIVILEGED)
    kusto(f".set-or-append WatchlistItems <| datatable(WatchlistAlias:string, SearchKey:string)[{rows}]")
    # Sentinel's built-in watchlist function
    kusto(".create-or-alter function _GetWatchlist(watchlistAlias:string) "
          "{ WatchlistItems | where WatchlistAlias == watchlistAlias }")


def load(events, now):
    """Replace every table's contents with one scenario's events."""
    for table in SCHEMAS:
        kusto(f".clear table {table} data")
    rows = {}
    for table, minutes_ago, fields in events:
        # a misspelled field would otherwise load as null and quietly hide the event from every rule
        if unknown := set(fields) - {column.split(":")[0] for column in SCHEMAS[table].split(", ")} - {"IngestDelay"}:
            raise ValueError(f"{table} has no column {', '.join(sorted(unknown))}")
        happened = now - timedelta(minutes=minutes_ago)
        defaults = {"TimeGenerated": happened, "CreatedAt": happened, "UpdatedAt": happened,
                    "IngestedAt": happened + timedelta(minutes=fields.get("IngestDelay", 2))}
        rows.setdefault(table, []).append(defaults | fields)
    for table, table_rows in rows.items():
        columns = [column.split(":") for column in SCHEMAS[table].split(", ")]
        values = ", ".join(literal(row.get(name), kind) for row in table_rows for name, kind in columns)
        kusto(f".set-or-append {table} <| datatable({SCHEMAS[table]})[{values}]")


def rules():
    for path in sorted(DETECTIONS.glob("*.yaml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        # every table exists here, so a fuzzy union could only hide a broken leg
        yield rule["name"].split()[0], rule, (rule["query"].replace("ingestion_time()", "IngestedAt")
                                              .replace("isfuzzy=true", "isfuzzy=false"))


STYLE = """
:root { color-scheme: light dark; --bg: #fff; --fg: #1f2328; --muted: #59636e; --line: #d1d9e0; --card: #f6f8fa;
        --pass: #1a7f37; --fail: #cf222e; --high: #bc4c00; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #3d444d; --card: #151b23;
          --pass: #3fb950; --fail: #f85149; --high: #f0883e; }
}
body { margin: 0 auto; max-width: 1100px; padding: 24px 16px; background: var(--bg); color: var(--fg);
       font: 15px/1.5 system-ui, sans-serif; }
h1 { margin: 0 0 4px; font-size: 1.6rem; }
h2 { margin: 2rem 0 .5rem; font-size: 1.15rem; }
.muted { color: var(--muted); }
.wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; vertical-align: top; padding: 6px 10px; border-bottom: 1px solid var(--line); }
.pass { color: var(--pass); font-weight: 700; }
.fail { color: var(--fail); font-weight: 700; }
details { margin: 8px 0; border: 1px solid var(--line); border-radius: 6px; background: var(--card); }
summary { padding: 10px 12px; cursor: pointer; }
details table { background: var(--bg); }
details th { width: 1%; white-space: nowrap; color: var(--muted); font-weight: 500; }
details td { font: 13px/1.5 ui-monospace, Consolas, monospace; overflow-wrap: anywhere; }
.sev { margin-left: 6px; padding: 1px 8px; border: 1px solid currentColor; border-radius: 99px; font-size: 12px; }
.High { color: var(--high); }
"""


def report(outcomes, rules_by_id, ran_at):
    """Render the replay as a standalone HTML page. Alert fields can be attacker-chosen, so everything is escaped."""
    esc = html.escape
    rows = "".join(f"<tr><td>{esc(scenario_id)}</td><td>{esc(title)}</td>"
                   f"<td>{esc(', '.join(sorted(expected)) or 'nothing')}</td>"
                   f"<td>{esc(', '.join(sorted(fired)) or 'nothing')}</td>"
                   f"<td class='{'pass' if passed else 'fail'}'>{'PASS' if passed else 'FAIL'}</td></tr>"
                   for scenario_id, title, expected, fired, passed in outcomes)
    alerts = []
    for scenario_id, title, _, fired, _ in outcomes:
        for rule_id, hits in sorted(fired.items()):
            rule = rules_by_id[rule_id]
            fields = "".join(f"<tr><th>{esc(name)}</th><td>{esc(value if isinstance(value, str) else json.dumps(value))}</td></tr>"
                             for name, value in hits[0].items())
            more = f" <span class='muted'>(first of {len(hits)} alerts)</span>" if len(hits) > 1 else ""
            alerts.append(f"<details><summary><b>{esc(scenario_id)}</b> {esc(title)}<br>fired <b>{esc(rule['name'])}</b>"
                          f"<span class='sev {esc(rule['severity'])}'>{esc(rule['severity'])}</span>{more}</summary>"
                          f"<div class='wrap'><table>{fields}</table></div></details>")
    passed = sum(outcome[-1] for outcome in outcomes)
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>Detection replay</title><style>{STYLE}</style></head><body>"
            f"<h1>Identity takeover detection: scenario replay</h1>"
            f"<p class='muted'>The five Sentinel rules, run against simulated logs on Microsoft's Kusto emulator, "
            f"{ran_at:%Y-%m-%d %H:%M} UTC</p>"
            f"<p class='{'pass' if passed == len(outcomes) else 'fail'}'>{passed} of {len(outcomes)} scenarios "
            f"behaved as expected</p>"
            f"<h2>Scenarios</h2><div class='wrap'><table><thead><tr><th>Scenario</th><th>What happens</th>"
            f"<th>Should fire</th><th>Fired</th><th>Result</th></tr></thead><tbody>{rows}</tbody></table></div>"
            f"<h2>Alerts</h2><p class='muted'>The first alert from each rule that fired, with the details an analyst "
            f"would see. Select one to expand it.</p>{''.join(alerts)}</body></html>")


def main():
    print(f"Waiting for the Kusto emulator at {KUSTO} ...", file=sys.stderr)
    wait_for_emulator()
    setup()
    detections = list(rules())
    lines, alerts, outcomes, failed = [], [], [], False
    ran_at = datetime.now(timezone.utc)
    for scenario_id, title, expected, events in SCENARIOS:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        load(events, now)
        fired = {}
        for rule_id, _, query in detections:
            try:
                # pin now() and ago() to the instant the records were placed relative to
                results = kusto(f"set query_now = {literal(now, 'datetime')};\n{query}")
            except RuntimeError as error:
                raise RuntimeError(f"{scenario_id} / {rule_id}: {error}") from None
            if results:
                fired[rule_id] = results
        # a rule must fire, and its alert must show the evidence it fired on
        missing = [f"{rule_id}: {text}" for rule_id, texts in expected.items() if rule_id in fired
                   for text in texts if text not in json.dumps(fired[rule_id])]
        if missing:
            print(f"{scenario_id} alert lacks {missing}", file=sys.stderr)
        passed = set(fired) == set(expected) and not missing
        failed = failed or not passed
        outcomes.append((scenario_id, title, expected, fired, passed))
        lines.append(f"| {scenario_id} | {title} | {', '.join(sorted(expected)) or 'nothing'} "
                     f"| {', '.join(sorted(fired)) or 'nothing'} | {'PASS' if passed else '**FAIL**'} |")
        alerts += [f"- **{scenario_id} -> {rule_id}:** {json.dumps(results[0])[:400]}" for rule_id, results in fired.items()]
    print("| Scenario | What happens | Should fire | Fired | Result |\n|---|---|---|---|---|")
    print("\n".join(lines))
    print("\nFirst alert from each rule that fired:\n")
    print("\n".join(alerts))
    if REPORT:
        Path(REPORT).write_text(report(outcomes, {rule_id: rule for rule_id, rule, _ in detections}, ran_at),
                                encoding="utf-8")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
