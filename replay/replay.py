"""Replay the lab scenarios through the detection rules on Microsoft's Kusto emulator.

Run from the repo root: docker compose run --rm replay
(or, with an emulator already listening: KUSTO_URL=http://127.0.0.1:8080 python replay/replay.py)
Prints a Markdown table of which rules fired per scenario and exits 1 if any scenario misbehaves.
"""
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
        yield rule["name"].split()[0], (rule["query"].replace("ingestion_time()", "IngestedAt")
                                        .replace("isfuzzy=true", "isfuzzy=false"))


def main():
    print(f"Waiting for the Kusto emulator at {KUSTO} ...", file=sys.stderr)
    wait_for_emulator()
    setup()
    detections = list(rules())
    lines, alerts, failed = [], [], False
    for scenario_id, title, expected, events in SCENARIOS:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        load(events, now)
        fired = {}
        for rule_id, query in detections:
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
        lines.append(f"| {scenario_id} | {title} | {', '.join(sorted(expected)) or 'nothing'} "
                     f"| {', '.join(sorted(fired)) or 'nothing'} | {'PASS' if passed else '**FAIL**'} |")
        alerts += [f"- **{scenario_id} -> {rule_id}:** {json.dumps(results[0])[:400]}" for rule_id, results in fired.items()]
    print("| Scenario | What happens | Should fire | Fired | Result |\n|---|---|---|---|---|")
    print("\n".join(lines))
    print("\nFirst alert from each rule that fired:\n")
    print("\n".join(alerts))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
