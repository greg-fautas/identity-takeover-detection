# Incident report: social-engineered account takeover

> **Lab exercise.** All identities, tickets and infrastructure are synthetic and live in an isolated test tenant.
> Fill in every [bracketed] item from your own run of scenarios S2 and S6 in the [lab guide](lab.md), using real log evidence. Delete this note when done.

| | |
|---|---|
| Incident | [Sentinel incident number] |
| Severity | High |
| Status | Closed, true positive (simulated) |
| Detected by | ITD-002, ITD-005 |
| Time to detect | [minutes from the reset to the first alert] |
| Analyst | [your name] |

## Executive summary

[Three or four sentences for a non-technical reader: what happened, how it was caught, the impact, and what changes as a result.]

## Timeline (UTC)

| Time | Source | Event |
|---|---|---|
| [hh:mm] | ServiceNow | [INC number] opened by phone: "[short description]" |
| [hh:mm] | AuditLogs | `it.operator` deleted Jordan Lee's MFA methods |
| [hh:mm] | AuditLogs | `it.operator` created a Temporary Access Pass for Jordan Lee |
| [hh:mm] | SigninLogs | Jordan Lee signed in from [IP, country], never seen before for this account |
| [hh:mm] | AuditLogs | Authenticator app registered from [IP] |
| [hh:mm] | Sentinel | ITD-002 fired ([incident number]) |
| [hh:mm] | AuditLogs | Consent to application: [app] |
| [hh:mm] | AuditLogs | Device registered: [device name] |
| [hh:mm] | Sentinel | ITD-005 fired |
| [hh:mm] | Response | Account disabled and sessions revoked |

## Detection

[Which rules fired and why, in plain terms. Include a screenshot of the ITD-002 alert's custom details showing the ticket number, the `phone` contact type and the new IP.]

## Investigation

[The evidence that confirmed the takeover. For each item, give the query you ran and a trimmed result.]

- [All sign-ins from the attacker IP]
- [Everything the account did after the reset]
- [The ticket record]

## ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1566.004 Phishing: Spearphishing Voice | Phone ticket [INC number] |
| Defense Evasion | T1656 Impersonation | Caller claimed to be Jordan Lee |
| Initial Access | T1078.004 Valid Accounts: Cloud Accounts | Sign-in from [IP] |
| Persistence | T1098.005 Account Manipulation: Device Registration | Authenticator added from [IP]; device [name] |
| Credential Access | T1528 Steal Application Access Token | Consent to [app] |

## Containment and recovery

[What you did, in order and with times: disabled the account, revoked sessions, removed the Temporary Access Pass, the attacker's MFA method, app grant and device, blocked the IP, re-verified the user in person or on video, and re-enrolled them.]

## Root cause

The service desk confirmed the caller's identity using details an attacker can find or guess. [Adjust to match what your scenario used.]

## What I missed or would change

[Be specific and honest: detection gaps, delays, false positives, and anything you had to tune.]

## Recommendations

- Verify callers out of band, through their manager or in person or on video with ID, never with details given on the call. A callback to the number on file can reach an attacker who has SIM-swapped the user.
- Require manager or second-person approval for privileged and MFA resets.
- Restrict security-info registration to trusted locations or compliant devices with a Conditional Access policy on the "Register security information" user action.
- Prefer phishing-resistant MFA (passkeys), and use short, single-use Temporary Access Passes for recovery.
- Send ticket data to the SIEM so every reset can be checked against its ticket.
