"""Copy recently updated ServiceNow incidents into the ServiceNowTickets_CL table in Microsoft Sentinel.

The detections join these tickets to Entra ID credential resets by user, so every reset can be
checked for ticket evidence. Settings come from environment variables (see docs/lab.md):
SN_INSTANCE, SN_USER, SN_PASSWORD, LOGS_INGESTION_ENDPOINT, DCR_IMMUTABLE_ID.
"""
import argparse
import json
import os
from datetime import datetime, timedelta, timezone

import requests
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient

STREAM = "Custom-ServiceNowTickets_CL"
# sys_created_on is set by the platform; opened_at is editable and could be backdated into a reset's window
FIELDS = ("number,sys_created_on,sys_updated_on,caller_id.email,opened_by.email,assigned_to.email,"
          "contact_type,short_description")
MAX_TICKETS = 1000  # newest first; far more than a lab updates between runs


def utc(snow_time):
    """ServiceNow returns stored date-times as 'YYYY-MM-DD HH:MM:SS' in UTC."""
    return datetime.strptime(snow_time, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def to_row(ticket):
    """Map a Table API record to a ServiceNowTickets_CL row. Emails are lowercased to match Entra UPNs."""
    updated = utc(ticket["sys_updated_on"]).isoformat()
    return {
        "TimeGenerated": updated,
        "TicketNumber": ticket["number"],
        "CreatedAt": utc(ticket["sys_created_on"]).isoformat(),
        "UpdatedAt": updated,
        "CallerUpn": ticket.get("caller_id.email", "").lower(),
        "OpenedByUpn": ticket.get("opened_by.email", "").lower(),
        "AssignedToUpn": ticket.get("assigned_to.email", "").lower(),
        "ContactType": ticket.get("contact_type", ""),
        "ShortDescription": ticket.get("short_description", ""),
    }


def fetch_tickets(since):
    response = requests.get(
        f"https://{os.environ['SN_INSTANCE']}.service-now.com/api/now/table/incident",
        auth=(os.environ["SN_USER"], os.environ["SN_PASSWORD"]),
        headers={"Accept": "application/json"},
        params={"sysparm_query": "ORDERBYDESCsys_updated_on", "sysparm_fields": FIELDS, "sysparm_limit": MAX_TICKETS},
        timeout=30,
    )
    response.raise_for_status()
    # Filtering here instead of in sysparm_query keeps all time handling in UTC.
    return [t for t in response.json()["result"] if utc(t["sys_updated_on"]) >= since]


def main():
    parser = argparse.ArgumentParser(description="Copy recently updated ServiceNow incidents into Microsoft Sentinel.")
    parser.add_argument("--lookback-minutes", type=int, default=180,
                        help="copy tickets updated in this window (default 180, so missed runs are caught up; "
                             "the rules ignore duplicate rows)")
    parser.add_argument("--dry-run", action="store_true", help="print the rows instead of uploading them")
    args = parser.parse_args()

    since = datetime.now(timezone.utc) - timedelta(minutes=args.lookback_minutes)
    rows = [to_row(t) for t in fetch_tickets(since)]
    if args.dry_run:
        print(json.dumps(rows, indent=2))
        return
    if rows:
        client = LogsIngestionClient(endpoint=os.environ["LOGS_INGESTION_ENDPOINT"], credential=DefaultAzureCredential())
        client.upload(rule_id=os.environ["DCR_IMMUTABLE_ID"], stream_name=STREAM, logs=rows)
    print(f"Uploaded {len(rows)} ticket(s) updated since {since:%Y-%m-%d %H:%M} UTC")


if __name__ == "__main__":
    main()
