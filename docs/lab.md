# Lab guide: build it, then attack it

The whole lab runs on free trials. When you're done, work through the teardown checklist in [step 10](#10-tear-down) so nothing keeps billing or stays weakened.

Throughout, `<tenant>` means your lab domain, such as `itdlab.onmicrosoft.com`.

## Before you start: keep the lab contained

- **Use your own device and network.** Never use an employer-managed laptop, network or VPN. The attack steps would land in your employer's security tools.
- **Use a separate account.** Sign up with a new personal Microsoft account, not a work or school address, and confirm the tenant domain before step 2.
- **Point every command at the lab tenant.** Always pass `-TenantId <tenant>` to `Connect-MgGraph`, so it can't reuse another tenant's session.
- **Keep your own PC out of the lab.** Register devices only on a throwaway VM, never on your own PC.

## 1. Accounts and trials

| What | Why | Where |
|---|---|---|
| New Azure account (personal Microsoft account) | Hosts the Log Analytics workspace and Sentinel. Signing up creates a new tenant. | azure.microsoft.com/free |
| Microsoft Entra ID P2 trial | Sending sign-in logs to Sentinel needs P1 or P2 | Microsoft 365 admin center → Billing → Purchase services |
| Microsoft Sentinel free trial | 31 days, up to 10 GB/day, on a new workspace | Starts when you enable Sentinel (step 3) |
| ServiceNow Personal Developer Instance (PDI) | Ticket source | developer.servicenow.com → Request Instance |
| Microsoft 365 E5 trial (optional) | Mailboxes, for the inbox-rule part of ITD-005 | Microsoft 365 admin center → Billing → Purchase services |

## 2. Lab identities

Create these accounts in the Entra admin center (Users → New user):

| Account | Entra roles | Plays |
|---|---|---|
| `jordan.lee@<tenant>` | none | The employee the attacker impersonates |
| `priya.shah@<tenant>` | Exchange Administrator | A privileged target (ITD-003) |
| `it.operator@<tenant>` | Helpdesk Administrator, Authentication Administrator | The admin who performs resets |
| `lab.user1` to `lab.user5@<tenant>` | none | Targets for the reset burst (ITD-004) |

The five lab users are quickest to create with Microsoft Graph PowerShell, signed in as your Global Administrator. Their passwords are thrown away because nobody signs in as them.

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -TenantId <tenant> -Scopes "User.ReadWrite.All"
1..5 | ForEach-Object {
    New-MgUser -DisplayName "Lab User $_" -UserPrincipalName "lab.user$_@<tenant>" -MailNickname "lab.user$_" `
        -AccountEnabled -PasswordProfile @{ Password = "Lab-$(New-Guid)"; ForceChangePasswordNextSignIn = $false }
}
```

Then turn on Temporary Access Pass for Jordan only:

1. Create a security group `itd-tap-pilot` with Jordan as its only member.
2. In the Entra admin center, go to Authentication methods → Policies → Temporary Access Pass.
3. Enable it for that group, and set **One-time use** to Yes.

## 3. Sentinel workspace

1. In the Azure portal, create a resource group `rg-itd-lab` and a Log Analytics workspace `law-itd-lab` in it.
2. Add Microsoft Sentinel to the workspace, then connect the workspace to the Microsoft Defender portal (security.microsoft.com), where Sentinel is now managed.
3. In the Defender portal, open Microsoft Sentinel → Content management → Content hub and install **Microsoft Entra ID**. Then open Configuration → Data connectors → Microsoft Entra ID and enable **Sign-in logs**, **Non-interactive user sign-in logs** and **Audit logs**.
4. Optional, for inbox rules: install **Microsoft 365** from the Content hub and enable its Exchange logs.
5. Create the watchlist: Configuration → Watchlist → New. Set name and alias to `PrivilegedAccounts`, upload this CSV, and choose `UserPrincipalName` as the search key. The service desk operator is on it too, because Helpdesk Administrator is a privileged role: whoever takes over that account can reset other people's credentials.

   ```csv
   UserPrincipalName
   priya.shah@<tenant>
   it.operator@<tenant>
   ```

## 4. ServiceNow

1. Request a PDI. It hibernates when idle; wake it from the developer portal before each session.
2. Go to User Administration → Users and create Jordan Lee, Priya Shah and Lab User 1 to 5. Set each **Email** to the exact Entra UPN, because the detections match tickets to accounts on that field.
3. Create the integration account `sentinel.integration`. Tick **Web service access only** and set a password. Give it two roles:
   - `itil`, so it can read incidents
   - `snc_read_only`, which blocks creating, updating and deleting records. Without it, `itil` could create tickets, and fake ticket evidence would silence ITD-001.

   To confirm it's read-only, sign in as the account and try to create an incident; it should be refused.

## 5. Ticket pipeline

1. In the Azure portal, go to Monitor → Data collection endpoints and create `dce-itd-lab` in the workspace's region.
2. In the workspace, go to Tables → Create → New custom log (DCR-based). Name the table `ServiceNowTickets`, create a new data collection rule `dcr-servicenow-tickets`, select `dce-itd-lab`, and upload [`ingestion/sample-ticket.json`](../ingestion/sample-ticket.json) as the sample. If the wizard asks for a transformation, use `source | extend TimeGenerated = todatetime(TimeGenerated)`.
   This creates the table `ServiceNowTickets_CL`, and the rule's input stream is `Custom-ServiceNowTickets_CL`.
3. Open the data collection rule (not the resource group or subscription), go to Access control (IAM), and give your own account the **Monitoring Metrics Publisher** role. If you'll run the script as a service principal, give it the same role in the same place.
4. Copy two values: the **Logs Ingestion** URI from the endpoint's Overview page, and the rule's `immutableId` from its JSON view.
5. Run the script from the `ingestion` folder. It signs in to Azure with your `az login` session. The password is entered at a prompt, so it never appears in your shell history.

   ```powershell
   python -m venv .venv; .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   $env:SN_INSTANCE = "dev12345"                # from your PDI URL
   $env:SN_USER = "sentinel.integration"
   $env:SN_PASSWORD = (Get-Credential sentinel.integration).GetNetworkCredential().Password
   $env:LOGS_INGESTION_ENDPOINT = "https://dce-itd-lab-xxxx.<region>-1.ingest.monitor.azure.com"
   $env:DCR_IMMUTABLE_ID = "dcr-<id>"
   az login --tenant <tenant>
   python servicenow_to_sentinel.py --dry-run --lookback-minutes 1440   # prints rows, uploads nothing
   python servicenow_to_sentinel.py --lookback-minutes 1440
   ```

   The first upload can take 5 to 15 minutes to appear. Check it in the Defender portal under Investigation & response → Hunting → Advanced hunting with `ServiceNowTickets_CL | take 10`.

During the scenarios, run `python servicenow_to_sentinel.py` after every ticket you create. Its default 3-hour lookback catches anything a missed run skipped, and the rules ignore duplicate rows.

To run it on a schedule with Task Scheduler:
- Store the settings as user environment variables, entering the password through `Get-Credential` as above: `[Environment]::SetEnvironmentVariable("SN_PASSWORD", <value>, "User")`.
- Point the task at the venv's `python.exe` and the script.
- Never put secrets in the task's arguments or in a script inside this repo.
- For a service principal, prefer a certificate (`AZURE_CLIENT_CERTIFICATE_PATH`) over a client secret.

## 6. Deploy the detections

First, check which operation names your tenant actually logs. Microsoft's reference and real tenants don't always agree. Run this after a test reset:

```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| summarize count() by OperationName, LoggedByService
| sort by OperationName asc
```

If a reset appears under a name that isn't in `CredentialResetOps`, add it to each rule.

Then, for each file in [`detections/`](../detections), open Microsoft Sentinel → Configuration → Analytics → Create → Scheduled query rule and copy the rule over:

| YAML field | Portal field |
|---|---|
| `name`, `description`, `severity`, `tactics`, `relevantTechniques` | General |
| `query` | Rule query |
| `entityMappings`, `customDetails`, `alertDetailsOverride` | Alert enhancement |
| `queryFrequency` | Run query every |
| `queryPeriod` | Lookup data from the last |
| `eventGroupingSettings` | Event grouping: trigger an alert for each event |

In Incident settings:
- Turn on **Create incidents**.
- Turn on **Alert grouping**, grouping alerts into one incident when the Account entity matches, within 1 day.

Grouping keeps one takeover from opening several incidents. Don't use alert suppression: it pauses the whole rule.

## 7. Baseline

Do this between 2 hours and 14 days before the scenarios; the day before is easiest. Sign in once as Jordan and as Priya from your normal network at https://myaccount.microsoft.com, and register Microsoft Authenticator for Jordan when prompted. ITD-002 uses these sign-ins to learn which networks are normal for each account.

## 8. Scenarios

Write down the start time of each scenario. Expected alert delays:
- ITD-002, ITD-003 and ITD-004: within about an hour, since they run hourly.
- ITD-005: within about an hour for consent and devices, 1 to 3 hours for inbox rules, because Exchange audit events arrive late.
- ITD-001: 2.5 to 3.5 hours after the reset, by design.

Run them in the order below, with S6 straight after S2, and use the same VPN exit for both.

### S1: benign reset (expect no alert)

1. In ServiceNow, open an incident with Caller *Jordan Lee*, Contact type *Phone*, Short description *Forgot password*. Run the ticket script.
2. Sign in to the Entra admin center as `it.operator`, open Users → Jordan Lee → Reset password.
3. As Jordan, on your normal network, sign in with the temporary password and set a new one.

Expected: no alert. ITD-001 finds the ticket, and ITD-002 sees a known network.

### S2: social-engineered takeover (expect ITD-002)

You play the caller, the operator who gets fooled, and the attacker.

1. **Caller.** Open an incident with Caller *Jordan Lee*, Contact type *Phone*, Short description *New phone, locked out, need MFA reset*. Run the ticket script, and wait until the ticket shows in `ServiceNowTickets_CL`.
2. **Operator.** As `it.operator`, open Jordan Lee → Authentication methods. Delete the registered methods, then add a Temporary Access Pass.
3. **Attacker.** Connect a VPN with an exit in another country, or use a phone hotspot. In a private browser window, go to https://mysignins.microsoft.com/security-info, sign in as Jordan with the pass, and add an authenticator app.

Expected: ITD-002 within about an hour. The alert should list the ticket number and contact type `phone`. Screenshot the incident and the alert's custom details for the report.

### S6: persistence (expect ITD-005)

Run this straight after S2, still as the attacker (VPN, private window, signed in as Jordan):

1. **OAuth consent.** Sign in to Graph Explorer (https://developer.microsoft.com/graph/graph-explorer) and accept the permissions prompt. If the tenant blocks it, go to Entra admin center → Enterprise apps → Consent and permissions. Allow user consent only for apps from verified publishers, for low-impact permissions, and set it back after this step.
2. **Device registration.** On a throwaway Windows VM, open Settings → Accounts → Access work or school → Connect and sign in as Jordan. The VM can be local (Hyper-V) or an Azure VM in `rg-itd-lab` with RDP open only to your IP and auto-shutdown on.
3. **Inbox rule (if you have mailboxes).** In Outlook on the web, add a rule that moves messages from IT into RSS Feeds.

Expected: ITD-005, listing the actions. Consent and device registration show within about an hour; the inbox rule can take 1 to 3 hours.

### S3: out-of-process reset (expect ITD-001)

Run this once you're done acting as the attacker, at least 3 hours after the last ticket for Jordan, because the rule accepts tickets created up to 2 hours either side. As `it.operator`, reset Jordan's password without opening a ticket. Don't sign in as Jordan from the VPN for the next 24 hours, or ITD-002 will tie that activity to this reset.

Expected: ITD-001 2.5 to 3.5 hours later.

### S4: privileged reset (expect ITD-003)

Sign in as your Global Administrator and reset Priya Shah's password. Helpdesk Administrators can reset only non-admins and a few limited admin roles; an Exchange Administrator needs a Privileged Authentication Administrator or a Global Administrator.

Expected: ITD-003 within about an hour, and ITD-001 2.5 to 3.5 hours later, since there's no ticket.

### S5: reset burst (expect ITD-004)

As `it.operator`, reset the five lab users. If Graph asks for admin consent, sign in once as your Global Administrator, consent on behalf of the organization, then reconnect as `it.operator`.

```powershell
Connect-MgGraph -TenantId <tenant> -Scopes "User-PasswordProfile.ReadWrite.All"
1..5 | ForEach-Object {
    Update-MgUser -UserId "lab.user$_@<tenant>" `
        -PasswordProfile @{ Password = "Lab-$(New-Guid)"; ForceChangePasswordNextSignIn = $true }
}
```

Expected: ITD-004 within about an hour, then ITD-001 for each account 2.5 to 3.5 hours later, since none had a ticket.

## 9. Capture evidence

For every scenario, save screenshots of the incident, the alert's custom details and the query results to `docs/images/`. Record the reset time and the alert time; the difference is your time to detect. Then fill in the Validation table in the [README](../README.md#validation) and write the [incident report](incident-report.md) from S2 and S6.

Before publishing anything:
- **Crop or blur your own identifiers in every screenshot:**
  - the signed-in account menu
  - tenant, subscription and workspace IDs
  - the endpoint hostname
  - your PDI instance name
  - every IP address except the VPN's (your home IP appears in the baseline and S1 sign-ins)
- **Check the repo for secrets.** Search it for passwords, client secrets and instance names, and turn on GitHub secret scanning push protection for the repository.

## 10. Tear down

Deleting the resource group removes only the Azure resources. Work through the whole list, or delete the lab tenant itself.

- [ ] Delete the `rg-itd-lab` resource group: workspace, endpoint, data collection rule and any VM.
- [ ] Disable the Temporary Access Pass policy, and delete the `itd-tap-pilot` group.
- [ ] Set user consent back to its previous setting.
- [ ] Revoke the tenant-wide consent for Microsoft Graph Command Line Tools (Enterprise apps → Microsoft Graph Command Line Tools → Permissions).
- [ ] Remove the attacker's authenticator from Jordan, and delete the VM's device registration (Devices → All devices).
- [ ] Delete any app registration or service principal you created for the script.
- [ ] Delete the scheduled task and the user environment variables (`SN_PASSWORD` and the others).
- [ ] Delete the `sentinel.integration` account in ServiceNow. The PDI itself is reclaimed after a period of inactivity.
- [ ] Check trial end dates in the Microsoft 365 admin center.
