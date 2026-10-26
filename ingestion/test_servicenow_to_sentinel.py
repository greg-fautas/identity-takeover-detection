import json
from pathlib import Path

from servicenow_to_sentinel import to_row

SAMPLE = Path(__file__).with_name("sample-ticket.json")


def test_to_row_matches_the_table_schema():
    row = to_row({
        "number": "INC0010001",
        "sys_created_on": "2026-10-26 14:03:11",
        "sys_updated_on": "2026-10-26 14:05:00",
        "caller_id.email": "Jordan.Lee@Contoso.onmicrosoft.com",
        "opened_by.email": "IT.Operator@Contoso.onmicrosoft.com",
        "assigned_to.email": "",
        "contact_type": "phone",
        "short_description": "New phone, locked out, need MFA reset",
    })
    assert row == {
        "TimeGenerated": "2026-10-26T14:05:00+00:00",
        "TicketNumber": "INC0010001",
        "CreatedAt": "2026-10-26T14:03:11+00:00",
        "UpdatedAt": "2026-10-26T14:05:00+00:00",
        "CallerUpn": "jordan.lee@contoso.onmicrosoft.com",
        "OpenedByUpn": "it.operator@contoso.onmicrosoft.com",
        "AssignedToUpn": "",
        "ContactType": "phone",
        "ShortDescription": "New phone, locked out, need MFA reset",
    }
    # The sample defines the custom table's columns (docs/lab.md step 5), so they must stay in sync
    assert row.keys() == json.loads(SAMPLE.read_text(encoding="utf-8"))[0].keys()


if __name__ == "__main__":
    test_to_row_matches_the_table_schema()
    print("ok")
