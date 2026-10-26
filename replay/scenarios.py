"""Simulated log records for each lab scenario, shaped like the Sentinel tables the rules read.

Times are minutes before the replay runs. replay.py sets IngestedAt (when a record reached the
workspace) to two minutes after the event, or IngestDelay minutes when an event sets it, and swaps
it in for ingestion_time(), which the emulator can't backdate.
"""
TENANT = "itdlab.onmicrosoft.com"
JORDAN, PRIYA, OPERATOR, ADMIN = (f"{name}@{TENANT}" for name in ("jordan.lee", "priya.shah", "it.operator", "admin"))
LAB1 = f"lab.user1@{TENANT}"
PRIVILEGED = [PRIYA, OPERATOR]  # the PrivilegedAccounts watchlist
HOME_IP, OPERATOR_IP, ATTACKER_IP = "198.51.100.23", "198.51.100.50", "203.0.113.47"  # documentation ranges
HOME_IP6, ATTACKER_IP6 = "2001:db8:a1:b2:3c4d:5e6f:7a8b:9c0d", "2001:db8:ff:47::1"  # different /64 networks
DAY = 24 * 60


def event(table, minutes_ago, **fields):
    return table, minutes_ago, fields


def reset(minutes_ago, target, operation="Reset password (by admin)", actor=OPERATOR):
    return event("AuditLogs", minutes_ago, OperationName=operation, Result="success",
                 InitiatedBy={"user": {"userPrincipalName": actor, "ipAddress": OPERATOR_IP}},
                 TargetResources=[{"type": "User", "userPrincipalName": target}])


def mfa_registered(minutes_ago, user, ip):
    return event("AuditLogs", minutes_ago, OperationName="User registered security info", Result="success",
                 InitiatedBy={"user": {"userPrincipalName": user, "ipAddress": ip}},
                 TargetResources=[{"type": "User", "userPrincipalName": user}])


def consent(minutes_ago, user, ip, app):
    return event("AuditLogs", minutes_ago, OperationName="Consent to application", Result="success",
                 InitiatedBy={"user": {"userPrincipalName": user, "ipAddress": ip}},
                 TargetResources=[{"type": "ServicePrincipal", "displayName": app}])


def device_owner(minutes_ago, user, device):
    return event("AuditLogs", minutes_ago, OperationName="Add registered owner to device", Result="success",
                 InitiatedBy={"app": {"displayName": "Device Registration Service"}},
                 TargetResources=[{"type": "Device", "displayName": device},
                                  {"type": "User", "userPrincipalName": user}])


def signin(minutes_ago, user, ip, country, app="My Signins"):
    return event("SigninLogs", minutes_ago, UserPrincipalName=user, IPAddress=ip, ResultType="0",
                 AppDisplayName=app, LocationDetails={"countryOrRegion": country})


def inbox_rule(minutes_ago, user, client_ip):
    return event("OfficeActivity", minutes_ago, Operation="New-InboxRule", UserId=user, ClientIP=client_ip,
                 Parameters='[{"Name":"MoveToFolder","Value":"RSS Feeds"}]')


def ticket(minutes_ago, number, caller, description, contact="phone"):
    return event("ServiceNowTickets_CL", minutes_ago, TicketNumber=number, CallerUpn=caller, OpenedByUpn=OPERATOR,
                 AssignedToUpn=OPERATOR, ContactType=contact, ShortDescription=description)


# Jordan and Priya signed in from home three days ago, so ITD-002 knows that network
BASELINE = [signin(3 * DAY, JORDAN, HOME_IP, "US"), signin(3 * DAY, PRIYA, HOME_IP, "US")]

# (id, what happens, {rule that must fire: text its alert must contain}, events)
# Each scenario is replayed on its own, at the moment its key rule runs: ITD-001 judges resets from
# 2.5-3.5 hours ago, the others judge what arrived in the last hour.
SCENARIOS = [
    ("S1", "Benign reset: ticketed, user signs in from home", {}, BASELINE + [
        ticket(190, "INC0010001", JORDAN, "Forgot password"),
        reset(180, f"Jordan.Lee@{TENANT}"),  # AuditLogs keep the directory's casing; ticket emails are lowercased
        signin(30, JORDAN, HOME_IP, "US"),
        reset(180, LAB1), ticket(80, "INC0010006", LAB1, "Forgot password"),  # ticket logged 100 min after the reset
        consent(30, PRIYA, HOME_IP, "Zoom"),  # persistence-type activity with no reset behind it: ITD-005 stays quiet
    ]),
    ("S2", "Social-engineered takeover: phone ticket, MFA reset, attacker enrolls MFA from abroad",
     {"ITD-002": ("Sign-in to My Signins", "User registered security info", "INC0010002")}, BASELINE + [
        ticket(50, "INC0010002", JORDAN, "New phone, locked out, need MFA reset"),
        reset(45, JORDAN, "Admin deleted security info"),
        reset(44, JORDAN, "Admin registered security info"),
        signin(35, JORDAN, ATTACKER_IP, "NL"),
        mfa_registered(33, JORDAN, ATTACKER_IP),
    ]),
    ("S3", "Out-of-process reset with no ticket", {"ITD-001": (JORDAN,)}, [
        reset(180, JORDAN, "Reset user password"),
    ]),
    ("S4", "Reset of a watchlisted admin", {"ITD-003": (PRIYA,)}, [
        reset(20, PRIYA, actor=ADMIN),
        # the same admin resets 3 more accounts through the portal (2 audit events each): 4 accounts, under ITD-004's 5
        *[reset(25 - n, f"lab.user{n}@{TENANT}", op, actor=ADMIN) for n in (1, 2, 3)
          for op in ("Reset password (by admin)", "Reset user password")],
    ]),
    ("S5", "One operator resets 5 accounts", {"ITD-004": ('"AccountsReset": 5',)}, [
        reset(30 - n, f"lab.user{n}@{TENANT}", "Reset user password") for n in range(1, 6)
    ]),
    ("S6", "Persistence after the takeover: app consent, device, inbox rule",
     {"ITD-005": ("Consent to application", "Add registered owner to device", "New-InboxRule")}, BASELINE + [
        ticket(305, "INC0010003", JORDAN, "New phone, locked out, need MFA reset"),
        reset(300, JORDAN, "Admin registered security info"),
        signin(290, JORDAN, ATTACKER_IP, "NL"),
        signin(41, JORDAN, ATTACKER_IP, "NL", app="Graph Explorer"),  # already alerted on, so ITD-002 stays quiet
        consent(40, JORDAN, ATTACKER_IP, "Graph Explorer"),
        device_owner(35, JORDAN, "DESKTOP-LAB01"),
        inbox_rule(30, JORDAN, f"{ATTACKER_IP}:51234"),
    ]),
    ("R1", "Regression: attacker waits almost a day after the reset, from IPv6", {"ITD-002": (ATTACKER_IP6,)}, BASELINE + [
        signin(3 * DAY, JORDAN, HOME_IP6, "US"),
        ticket(1440, "INC0010004", JORDAN, "Forgot password"),
        reset(1435, JORDAN),  # 23h45m before the sign-in: past the 8h default max TAP lifetime, inside FollowOn
        signin(10, JORDAN, ATTACKER_IP6, "NL"),
    ]),
    ("R2", "Regression: user's IPv6 address changed overnight, same home network", {}, [
        signin(3 * DAY, JORDAN, HOME_IP6, "US"),
        ticket(65, "INC0010005", JORDAN, "Forgot password"),
        reset(60, JORDAN),
        signin(30, JORDAN, "2001:db8:a1:b2:1111:2222:3333:4444", "US"),
    ]),
    ("R3", "Regression: tickets exist, but none covers the reset", {"ITD-001": (JORDAN,)}, [
        ticket(310, "INC0010007", JORDAN, "Forgot password"),  # 130 min before the reset: outside the 2h window
        ticket(185, "INC0010008", PRIYA, "Forgot password"),   # in the window, but another caller; same operator
        reset(180, JORDAN, "Reset user password"),
    ]),
    ("R4", "Regression: mail forwarding set 2.5 hours ago, Exchange event arrived 20 minutes ago",
     {"ITD-005": ("Set-Mailbox", f'"IPAddress": "{ATTACKER_IP6}"')}, [
        ticket(245, "INC0010009", JORDAN, "New phone, locked out, need MFA reset"),
        reset(240, JORDAN, "Admin registered security info"),
        event("OfficeActivity", 150, Operation="Set-Mailbox", UserId=JORDAN, ClientIP=f"[{ATTACKER_IP6}]:443",
              Parameters='[{"Name":"ForwardingSmtpAddress","Value":"smtp:jl.backup@example.net"},'
                         '{"Name":"DeliverToMailboxAndForward","Value":"True"}]', IngestDelay=130),
    ]),
    ("R5", "Regression: watchlisted admin's password reset through self-service (SIM-swap route)",
     {"ITD-003": (PRIYA,)}, [
        event("AuditLogs", 20, OperationName="Reset password (self-service)", Result="success",
              InitiatedBy={"user": {"userPrincipalName": PRIYA, "ipAddress": ATTACKER_IP}},
              TargetResources=[{"type": "User", "userPrincipalName": PRIYA}]),
    ]),
]
