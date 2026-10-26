# Identity Takeover Detection

Microsoft Sentinel detections for social-engineered account takeover. In this attack, someone phones the IT service desk pretending to be an employee, gets that employee's password or MFA reset, and signs in as them.

Scattered Spider used this method in the 2023 MGM Resorts breach and keeps using it ([CISA advisory AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)). Every step uses valid credentials and normal admin tools, so endpoint security has no malware to catch. The evidence is split between identity logs, which most SIEMs collect, and the ticketing system, which most don't.

This project feeds ServiceNow tickets into Sentinel alongside Entra ID audit and sign-in logs. Five KQL analytics rules follow the attack from the reset onward. The lab includes an attack simulation for each rule, a benign reset that should stay silent, and a triage playbook for the analyst who gets the alert.

**Stack:** Microsoft Sentinel · KQL · Entra ID · ServiceNow REST API · Python (Azure Monitor Logs Ingestion API) · MITRE ATT&CK · GitHub Actions

## The attack chain

| Step | What the attacker does | ATT&CK | Caught by |
|---|---|---|---|
| 1 | Gathers employee details from LinkedIn and breach data | T1589 | Not visible in logs |
| 2 | Calls the service desk posing as the employee | T1566.004, T1656 | The phone ticket is shown as context in ITD-002 alerts |
| 3 | Gets the password or MFA reset, which is logged as routine admin work | T1098 | ITD-001, ITD-003, ITD-004 |
| 4 | Enrolls their own MFA and signs in from a new network | T1098.005, T1078.004 | ITD-002 |
| 5 | Keeps access with an OAuth consent, a registered device, or mail rules and forwarding | T1528, T1564.008, T1114.003 | ITD-005 |

## A ticket isn't proof

The obvious rule is "alert on any reset that has no ticket." That rule misses the real attack. When the attacker calls, the analyst opens a ticket and follows the process, so the ticket exists. It just doesn't prove who was on the phone.

So the rules split the problem:

- **ITD-001** catches resets that skip the ticket process. That points to a compromised or insider admin account.
- **ITD-002** assumes the process can be fooled and watches what the account does next. An alert fires when, within 24 hours of the reset, the account signs in or enrolls MFA from a network it has never used. The alert carries the ticket number and contact channel, so the analyst sees right away that the reset was requested by phone.

## Detections

| ID | Detection | Fires when | Severity | ATT&CK |
|---|---|---|---|---|
| [ITD-001](detections/ITD-001-credential-reset-without-ticket.yaml) | Credential reset with no ticket evidence | An admin resets a user's password or MFA and no ticket for that user was created within 2 hours either side | Medium | T1078.004, T1098 |
| [ITD-002](detections/ITD-002-takeover-after-credential-reset.yaml) | Account takeover sequence after credential reset | Within 24 hours of a reset, the account signs in or registers MFA from a network it has never signed in from | High | T1566.004, T1656, T1078.004, T1098.005 |
| [ITD-003](detections/ITD-003-privileged-account-credential-reset.yaml) | Credential reset on a privileged account | Any reset of an account on the `PrivilegedAccounts` watchlist, including self-service and app-made resets | High | T1098, T1078.004 |
| [ITD-004](detections/ITD-004-credential-reset-burst.yaml) | Credential reset burst by a single operator | One admin resets 5 or more accounts within an hour | Medium | T1531, T1098 |
| [ITD-005](detections/ITD-005-persistence-after-credential-reset.yaml) | Persistence after credential reset | Within 24 hours of a reset: OAuth consent, device registration, an inbox rule, or mail forwarding | Medium | T1098.005, T1564.008, T1114.003, T1528 |

Each rule is a Sentinel analytics rule template with the KQL, schedule, ATT&CK mapping, entity mapping (accounts and IPs) and custom alert details. Rules judge events when they reach the workspace, not when they happened, so logs that arrive late (Exchange audit events often take over an hour) are still evaluated.

CI checks everything on each push:
- [`validate_detections.py`](scripts/validate_detections.py) checks required fields, ATT&CK IDs and Sentinel's schedule limits.
- Microsoft's Kusto parser type-checks every query in the rules and docs, and confirms that every column a rule maps to an entity or alert field exists ([`check_kql.js`](scripts/check_kql.js)).
- `pip-audit` scans the Python dependencies for known vulnerabilities.

## ATT&CK coverage

| Tactic | Technique | Rules |
|---|---|---|
| Initial Access | T1566.004 Phishing: Spearphishing Voice | ITD-002 |
| Defense Evasion | T1656 Impersonation | ITD-002 |
| Initial Access, Persistence | T1078.004 Valid Accounts: Cloud Accounts | ITD-001, ITD-002, ITD-003 |
| Persistence, Privilege Escalation | T1098 Account Manipulation | ITD-001, ITD-003, ITD-004 |
| Persistence | T1098.005 Account Manipulation: Device Registration | ITD-002, ITD-005 |
| Credential Access | T1528 Steal Application Access Token | ITD-005 |
| Defense Evasion | T1564.008 Hide Artifacts: Email Hiding Rules | ITD-005 |
| Collection | T1114.003 Email Collection: Email Forwarding Rule | ITD-005 |
| Impact | T1531 Account Access Removal | ITD-004 |

## Architecture

```text
ServiceNow incidents ──> servicenow_to_sentinel.py ──┐ (Logs Ingestion API → ServiceNowTickets_CL)
Entra ID: AuditLogs, SigninLogs ─────────────────────┤
Microsoft 365: OfficeActivity (optional) ────────────┼──> Microsoft Sentinel workspace
Watchlist: PrivilegedAccounts ───────────────────────┘    │
                                                          ▼
                                                          Analytics rules ITD-001 to ITD-005
                                                          │
                                                          ▼
                                                          Incidents, worked with the triage playbook
```

## Validation

Each scenario is run in the lab ([docs/lab.md](docs/lab.md#8-scenarios)) and the results are recorded here.

<!-- Fill in Result after each run: time to detect, plus a link to a redacted screenshot in docs/images/. -->

| Scenario | What happens | Should fire | Result |
|---|---|---|---|
| S1 Benign reset | Ticketed reset; the user signs in from their usual network | Nothing | |
| S2 Social-engineered takeover | Phone ticket, MFA reset and Temporary Access Pass; the "attacker" signs in and enrolls MFA through a VPN exit in another country | ITD-002 | |
| S3 Out-of-process reset | Reset with no ticket | ITD-001 | |
| S4 Privileged reset | Reset of a watchlisted admin, no ticket | ITD-003 (plus ITD-001) | |
| S5 Reset burst | One operator resets 5 accounts in a few minutes | ITD-004 (plus ITD-001 for each account) | |
| S6 Persistence | OAuth consent, device registration and an inbox rule after S2 | ITD-005 | |

## Repository layout

```
detections/   Sentinel analytics rules, one YAML file per rule
ingestion/    ServiceNow-to-Sentinel ticket pipeline and its test
docs/         lab.md (build and attack the lab), triage-playbook.md, incident-report.md
scripts/      validate_detections.py, extract_kql.py and check_kql.js, run by CI on every push
```

## Documentation

- [Lab guide](docs/lab.md): build the lab tenant, connect the data, run the six scenarios, and tear it all down.
- [Triage playbook](docs/triage-playbook.md): how to work each alert, when to escalate, and how to contain.
- [Incident report](docs/incident-report.md): a full write-up of the S2 takeover from first call to containment.

## Limitations and tuning

These are the gaps, including how an attacker who knows these rules would try to get past them.

- **Operation names drift.** Entra ID audit names vary between tenants and change over time. Check yours with `AuditLogs | summarize count() by OperationName`, and update `CredentialResetOps` in each rule.
- **A ticket proves little to ITD-001.** Any ticket for the user satisfies it, including one created after the reset by the insider the rule is meant to catch. It catches a skipped process, not an abused one. Anyone who can write ServiceNow incidents, or who holds Monitoring Metrics Publisher on the data collection rule, can add ticket evidence. Tickets are matched to accounts by the caller's email, which must equal their Entra UPN.
- **Familiar networks look safe to ITD-002.** An insider in the same office, or an attacker already on the corporate network or on a residential proxy near the victim, isn't "new". Device signals, such as an unregistered or unmanaged device, are the stronger upgrade. In production, network novelty also needs tuning for mobile carriers and for users with no sign-in history.
- **Pacing gets past ITD-004.** Four resets an hour, or resets spread across two admin accounts, stay under the threshold.
- **Human operators only, except ITD-003.** ITD-001, 002, 004 and 005 ignore resets made by applications using their own credentials (app-only Graph calls). ITD-003 includes those, and self-service resets, for watchlisted accounts. "Privileged" means whatever the watchlist says; in production, generate the list from privileged role assignments, both active and eligible.
- **Entra ID cloud resets only.** The rules don't see resets in on-premises AD for synced accounts, resets in another identity provider, or service desk changes that weaken MFA without a reset, such as adding a user to a Conditional Access exclusion group.
- **Scale.** ITD-002 reads 14 days of sign-ins every hour. That's fine for a lab; at scale, keep a summarized baseline table.
- **Some alert fields are attacker-controlled.** App names, device names and inbox-rule parameters are chosen by the attacker. Treat them as untrusted if alerts ever feed automation or AI triage.

## Lab safety

Everything runs in a dedicated lab tenant, with synthetic users and tickets, on a personal device and network. No production systems, employer data or real internal procedures are used.
