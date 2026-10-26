# Triage playbook

Every alert in this project comes down to one question: did the real account owner ask for this reset? Aim to answer it within the first 15 minutes.

## Ground rules

- **Verify out of band.** Use the user's manager, or in person or on video with ID. Never use a number or email from the ticket or from the caller. For ITD-002 and ITD-003, don't rely on a callback either, even to the number on file. This group is known for SIM swapping, so the callback may reach the attacker.
- **Ticket text is a claim, not evidence.** The short description and contact type record what the caller said, not what anyone verified.
- **Treat alert fields as untrusted.** App names, device names and inbox-rule parameters are chosen by the attacker.
- **Assume the attacker is still active.** They may still be on the phone with the service desk, or signed in. When the evidence points to a takeover, contain first and explain afterwards.
- **Record every decision on the incident:** what you checked, what you found, and why you closed or escalated.

## ITD-002 Account takeover sequence after credential reset (High)

Within 24 hours of a reset, the account was used from a network it had never signed in from. Of all the rules, this is the one most likely to be a live takeover.

**Investigate**

1. Read the custom details: who reset the account, the ticket numbers and contact type, the new IPs and countries, and what the account did. "none" under tickets can also mean the ticket hadn't reached Sentinel when the rule ran, so check ServiceNow before treating the reset as out of process.
2. Check whether the new IP touches other accounts ([query](#sign-ins-from-an-ip)). Several accounts from one IP means a campaign.
3. List everything the account did since the reset ([query](#everything-an-account-did-since-a-time)).
4. Find which MFA methods were added and from where. Match each "User registered security info" audit event to its IP. A method registered from the new IP is the attacker's.
5. Contact the user through their manager or in person. Did they call the service desk? Where are they right now?

**True positive** if the user didn't make the call, isn't at that location, or doesn't recognize the new method or device.

**Benign** if the verified user confirms the request, the location and the device (for example, they're travelling). Record what you verified.

**Contain**, in this order ([commands](#containment-commands)):

1. Disable the account, then revoke its sessions. Access tokens already issued stay valid for up to about an hour, so keep watching the account. For accounts synced from on-premises AD, disable them there too, or the next sync turns the account back on.
2. Delete the Temporary Access Pass and the attacker's MFA methods, reset the password, and disable any device the attacker registered. Re-verify the user in person or on video before re-enrolling them.
3. Block the IP with a Conditional Access policy that blocks a named location containing it. This only slows an attacker who can rotate proxies.
4. Remove persistence. Check ITD-005 and the account's activity for app consents, registered devices, inbox rules and mail forwarding.
5. Look for the caller's other attempts: other phone tickets that day, other resets by the same operator, and the caller ID in the phone system (it can be spoofed).

**Escalate** to incident response right away if the account is privileged, data was accessed, or the IP hits other accounts.

## ITD-001 Credential reset with no ticket evidence (Medium)

An admin reset someone's credentials and no ticket for that user was created within 2 hours either side.

**Investigate**

1. Ask the operator why they made the reset, through a channel other than their own account. A ticket logged late or never is the most common benign cause.
2. Check the operator's own sign-ins around the reset for a new IP or device, or impossible travel ([query](#sign-ins-for-an-account)). A compromised admin account is the dangerous explanation.
3. Check whether the target account was used after the reset ([query](#everything-an-account-did-since-a-time)).

**Benign** if the operator confirms the reset and the user requested it; ask the operator to log the ticket. Repeated cases are a process problem, so report them to the service desk lead.

**Escalate** if the operator didn't make the reset or their session looks compromised. Disable the operator account, revoke its sessions, and review every action it took ([query](#everything-an-operator-did)).

## ITD-003 Credential reset on a privileged account (High)

1. Confirm with the admin through their manager or in person. A self-service reset the admin didn't make points to a SIM swap.
2. Review the account's sign-ins and directory changes since the reset ([query](#everything-an-account-did-since-a-time)).

**Escalate** immediately if the admin doesn't confirm. Disable the account, revoke its sessions, and review the changes it made to role assignments, app credentials and Conditional Access policies.

## ITD-004 Credential reset burst by a single operator (Medium)

1. Check with the service desk lead for a planned bulk change, such as a cleanup after a phishing incident or a new-starter batch.
2. Review the operator's sign-ins for a new IP or device ([query](#sign-ins-for-an-account)).
3. Check whether any of the reset accounts were then used from new networks (ITD-002).

**Escalate** if there's no planned change. Treat the operator account as compromised: contain it first, then each reset account.

## ITD-005 Persistence after credential reset (Medium)

1. Compare the IP with any ITD-002 alert for the same account. A match all but confirms the takeover.
2. **OAuth consent:** which app, which permissions, and is the publisher verified? Remove the grant if the user doesn't recognize the app.
3. **Device:** is it a device the user owns? If not, disable and delete it.
4. **Inbox rule or forwarding:** does it forward mail outside the company, delete messages, or move them to rarely opened folders such as RSS Feeds or Archive? Remove it and review the mail it touched.

## Hunting queries

### Sign-ins from an IP

```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d) and IPAddress == "<ip>"
| summarize Attempts = count(), Successes = countif(ResultType == "0"), Apps = make_set(AppDisplayName)
    by UserPrincipalName
```

### Sign-ins for an account

```kusto
union
    (SigninLogs
        | extend Type = "interactive", Country = tostring(LocationDetails.countryOrRegion), Device = tostring(DeviceDetail.displayName)),
    (AADNonInteractiveUserSignInLogs
        | extend Type = "non-interactive", Country = tostring(parse_json(LocationDetails).countryOrRegion),
                 Device = tostring(parse_json(DeviceDetail).displayName))
| where TimeGenerated > ago(7d) and UserPrincipalName =~ "<upn>"
| project TimeGenerated, Type, IPAddress, Country, AppDisplayName, ResultType, Device, UserAgent
| sort by TimeGenerated desc
```

### Everything an account did since a time

```kusto
let Upn = "<upn>";
let Since = datetime(<reset time, UTC>);
union isfuzzy=true
    (SigninLogs
        | where TimeGenerated > Since and UserPrincipalName =~ Upn
        | project TimeGenerated, Source = "Sign-in", Action = AppDisplayName, IPAddress,
                  Detail = tostring(LocationDetails.countryOrRegion)),
    (AADNonInteractiveUserSignInLogs
        | where TimeGenerated > Since and UserPrincipalName =~ Upn
        | project TimeGenerated, Source = "Sign-in (non-interactive)", Action = AppDisplayName, IPAddress,
                  Detail = tostring(parse_json(LocationDetails).countryOrRegion)),
    (AuditLogs
        | where TimeGenerated > Since
        | where tostring(InitiatedBy.user.userPrincipalName) =~ Upn or tostring(TargetResources) contains Upn
        | project TimeGenerated, Source = "Audit", Action = OperationName, IPAddress = tostring(InitiatedBy.user.ipAddress),
                  Detail = tostring(TargetResources[0].displayName)),
    (OfficeActivity
        | where TimeGenerated > Since and UserId =~ Upn
        | project TimeGenerated, Source = "Microsoft 365", Action = Operation, IPAddress = ClientIP, Detail = tostring(Parameters))
| sort by TimeGenerated asc
```

### Everything an operator did

```kusto
AuditLogs
| where TimeGenerated > ago(1d)
| where tostring(InitiatedBy.user.userPrincipalName) =~ "<operator upn>"
| project TimeGenerated, OperationName, Target = tostring(TargetResources[0].userPrincipalName),
          IPAddress = tostring(InitiatedBy.user.ipAddress), Result
| sort by TimeGenerated asc
```

### Tickets for a user

`OpenedByUpn` shows who created the ticket. An operator who opens a ticket after their own reset stands out here.

```kusto
ServiceNowTickets_CL
| where CallerUpn =~ "<upn>"
| summarize arg_max(todatetime(UpdatedAt), *) by TicketNumber
| project CreatedAt, TicketNumber, ContactType, OpenedByUpn, AssignedToUpn, ShortDescription
```

## Containment commands

These use Microsoft Graph PowerShell, signed in with a role that can manage the account. Disabling an admin needs a Privileged Authentication Administrator.

```powershell
Connect-MgGraph -TenantId <tenant> -Scopes "User.EnableDisableAccount.All", "User.Read.All", "User.RevokeSessions.All", "UserAuthenticationMethod.Read.All"
Update-MgUser -UserId "<upn>" -AccountEnabled:$false       # 1. block new sign-ins
Revoke-MgUserSignInSession -UserId "<upn>"                 # 2. revoke refresh tokens; issued access tokens live up to ~1 hour
Get-MgUserAuthenticationMethod -UserId "<upn>"             # 3. list methods, then delete the pass and attacker methods in the Entra admin center
```

Disable the attacker's registered devices in the Entra admin center (Devices → All devices).
