# Phase 1 — Brute Force Detection

## Concept / Definition

A brute force attack is when an attacker repeatedly attempts to log into an account
by trying many passwords in rapid succession. The goal is to guess the correct
credentials through volume rather than skill.

## Analogy

Imagine someone standing at a door trying every key on a large keyring one by one
until one works. The attack is not clever — it relies on persistence and speed.

## What We Built

A Python script that reads security log files, extracts failed login attempts,
groups them by IP address, and detects when 3 or more failures occur within a
5 second window.

## Detection Logic

- Read each line of the log file
- Extract: timestamp, username, IP address, event type
- Group failed logins by IP address
- Apply sliding window: if 3 attempts occur within 5 seconds → alert
- Assign severity based on total attempt count:
  - MEDIUM : 3 to 4 attempts
  - HIGH : 5 to 9 attempts
  - CRITICAL: 10 or more attempts

## Key Terms

| Term             | Definition                                                                    |
| ---------------- | ----------------------------------------------------------------------------- |
| Brute Force      | Repeated login attempts to guess credentials                                  |
| Sliding Window   | A time-based detection technique checking N events within X seconds           |
| Threshold        | The limit you set to decide when behaviour becomes suspicious                 |
| Threshold Tuning | Adjusting detection limits based on environment and false positive rate       |
| Severity Tiering | Ranking alerts by danger level — MEDIUM / HIGH / CRITICAL                     |
| IOC              | Indicator of Compromise — evidence of malicious activity (e.g. suspicious IP) |
| Alert Fatigue    | When too many alerts cause analysts to stop paying attention                  |

## Key Commands / Tools

```python
# Regex to extract IP address
ip_match = re.search(r"ip:([\d\.]+)", line)

# Regex to extract timestamp
time_match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)

# Convert string to datetime object
time = datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S")

# Sliding window check
diff = (times[i + 2] - times[i]).total_seconds()
if diff <= 5:
    # Brute force detected
```

## Real World Technologies

The same detection logic runs inside:

- Splunk Enterprise
- Microsoft Sentinel
- Elastic Security
- Wazuh
- Suricata

## Exam Tip

Brute force detection relies on TIME and VOLUME together — not just the number
of failures. An attacker who fails 100 times over 24 hours looks very different
from one who fails 5 times in 3 seconds. Always consider the time window.
