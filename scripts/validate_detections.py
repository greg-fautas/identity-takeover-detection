"""Validate the Sentinel analytics rules in detections/. Runs in CI on every push."""
import re
import sys
import uuid
from pathlib import Path

import yaml

DETECTIONS = Path(__file__).resolve().parent.parent / "detections"
REQUIRED = {"id", "name", "description", "severity", "requiredDataConnectors", "queryFrequency", "queryPeriod",
            "triggerOperator", "triggerThreshold", "tactics", "relevantTechniques", "query", "entityMappings",
            "version", "kind"}
SEVERITIES = {"Informational", "Low", "Medium", "High"}
TACTICS = {"Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
           "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
           "Collection", "Exfiltration", "CommandAndControl", "Impact", "PreAttack",
           "ImpairProcessControl", "InhibitResponseFunction"}
TECHNIQUE = re.compile(r"T\d{4}(\.\d{3})?")
DURATION = re.compile(r"(\d+)([mhd])")
MINUTES = {"m": 1, "h": 60, "d": 1440}


def minutes(value):
    match = DURATION.fullmatch(str(value))
    return int(match[1]) * MINUTES[match[2]] if match else None


def check(rule):
    """Yield a message for each problem in one parsed rule."""
    if not isinstance(rule, dict):
        yield "not a YAML mapping"
        return
    missing = REQUIRED - rule.keys()
    if missing:
        yield f"missing {', '.join(sorted(missing))}"
        return
    try:
        uuid.UUID(str(rule["id"]))
    except ValueError:
        yield f"id is not a GUID: {rule['id']}"
    if rule["severity"] not in SEVERITIES:
        yield f"severity must be one of {', '.join(sorted(SEVERITIES))}"
    if rule["kind"] != "Scheduled":
        yield "kind must be Scheduled"
    for tactic in set(rule["tactics"]) - TACTICS:
        yield f"unknown tactic {tactic}"
    for technique in rule["relevantTechniques"]:
        if not TECHNIQUE.fullmatch(str(technique)):
            yield f"bad technique ID {technique}"
    frequency, period = minutes(rule["queryFrequency"]), minutes(rule["queryPeriod"])
    if frequency is None or period is None:
        yield "queryFrequency and queryPeriod must look like 30m, 1h or 14d"
    elif not 5 <= frequency <= period <= 14 * 1440:
        yield "need 5m <= queryFrequency <= queryPeriod <= 14d"
    elif period >= 2 * 1440 and frequency < 60:
        yield "a queryPeriod of 2d or more needs a queryFrequency of at least 1h"
    if not str(rule["query"]).strip():
        yield "query is empty"
    for field, text in rule.get("alertDetailsOverride", {}).items():
        if str(text).count("{{") > 3:
            yield f"alertDetailsOverride.{field} has more than 3 {{{{Column}}}} parameters"


def main():
    paths = sorted(DETECTIONS.glob("*.yaml"))
    seen, failed = {}, not paths
    for path in paths:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        problems = list(check(rule))
        rule_id = rule.get("id") if isinstance(rule, dict) else None
        if rule_id in seen:
            problems.append(f"duplicate id, also used by {seen[rule_id]}")
        seen[rule_id] = path.name
        for problem in problems:
            print(f"{path.name}: {problem}")
        failed = failed or bool(problems)
    print(f"Checked {len(paths)} rule(s)")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
