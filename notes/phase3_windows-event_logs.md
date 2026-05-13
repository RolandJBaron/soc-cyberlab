# Phase 3 — Windows Event Log Parsing

## Concept / Definition

Windows records all security-related activity in the Security Event Log. Every
failed login, successful login, account creation, and privilege escalation is
stored as a numbered event. SOC analysts read these events to detect attacks
on Windows systems.

## Analogy

Windows keeps a security diary. Every time someone tries to open a door —
successfully or not — it writes an entry. The Security Event Log is that diary.
A SOC analyst reads it looking for suspicious patterns.

## Key Event IDs

| Event ID | Meaning                                   |
| -------- | ----------------------------------------- |
| 4624     | Successful logon                          |
| 4625     | Failed logon                              |
| 4648     | Logon using explicit credentials          |
| 4672     | Special privileges assigned — admin logon |
| 4720     | User account created                      |
| 4726     | User account deleted                      |

## What We Built

A parser that reads exported Windows Security logs, splits the file into individual
event blocks, and extracts key fields from each block using regex. It then applies
the same brute force detection logic from Phase 1 against real Windows event data.

## Log Format Difference

Our sample logs (simple, one line per event):
2026-01-01 10:00:01 LOGIN_FAILED user:admin ip:10.0.0.5
Windows Security logs (complex, 50+ lines per event):
Event[0]
Log Name: Security
Date: 2026-05-13T12:10:51.0000000Z
Event ID: 4625
Account For Which Logon Failed:
Account Name: testuser
Network Information:
Source Network Address: ::1
Failure Reason: Unknown user name or bad password.

## Key Differences From Sample Log Parsing

| Feature           | Sample Logs  | Windows Event Logs      |
| ----------------- | ------------ | ----------------------- |
| Format            | Single line  | Multi-line block        |
| Splitting         | Line by line | Split on Event[N]       |
| IP format         | IPv4 only    | IPv4 and IPv6           |
| Encoding          | UTF-8        | UTF-16                  |
| Username location | Inline       | Inside specific section |

## Detection Logic

- Export logs using wevtutil
- Read file with UTF-16 encoding
- Split content into individual event blocks using regex
- Extract timestamp, username, IP, and failure reason from each block
- Skip events with blank username or IP (Windows system noise)
- Apply brute force detection logic from Phase 1

## Key Commands / Tools

```powershell
# Export failed logins from Windows Security log
wevtutil qe Security "/q:*[System[EventID=4625]]" /c:100 /rd:true /f:text > logs/windows_failed_logins.log

# Check audit policy
auditpol /get /category:"Logon/Logoff"

# Create test user
net user testuser TempPass123! /add

# Delete test user
net user testuser /delete
```

```python
# Read UTF-16 encoded Windows log file
with open(log_path, "r", encoding="utf-16", errors="ignore") as f:
    content = f.read()

# Split into individual event blocks
events = re.split(r"Event\[\d+\]", content)

# Extract username from failed logon section
user_match = re.search(
    r"Account For Which Logon Failed:.*?Account Name:\s+(\S+)",
    event, re.DOTALL
)

# re.DOTALL allows regex to match across multiple lines
```

## Key Terms

| Term               | Definition                                                        |
| ------------------ | ----------------------------------------------------------------- |
| Event ID           | A number that identifies the type of security event in Windows    |
| Security Event Log | Windows log that records all authentication and security activity |
| wevtutil           | Windows command line tool for querying and exporting event logs   |
| UTF-16             | Character encoding used by Windows for event log exports          |
| ::1                | IPv6 loopback address — equivalent to 127.0.0.1, means localhost  |
| re.DOTALL          | Python regex flag that allows . to match newline characters       |
| Logon Type 2       | Interactive logon — a human sitting at the machine                |
| Logon Type 3       | Network logon — remote authentication over the network            |
| Logon Type 5       | Service logon — Windows background service authenticating         |

## Real World Context

In enterprise SOC environments Windows Event Logs are forwarded automatically
to a SIEM using agents like:

- Splunk Universal Forwarder → Splunk
- Microsoft Monitoring Agent → Microsoft Sentinel
- Wazuh Agent → Wazuh
- Winlogbeat → Elastic Security

Analysts never export logs manually with wevtutil. That process is automated.
What you built manually is exactly what those agents do automatically at scale.

## Exam Tip

Know your Event IDs. In any SOC analyst exam or interview you will be expected
to know that 4625 is a failed logon and 4624 is a successful logon without
looking them up. The most critical ones to memorise are 4624, 4625, 4672, and 4720.
