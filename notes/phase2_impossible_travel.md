# Phase 2 — Impossible Travel Detection

## Concept / Definition

Impossible travel is when the same user account appears from two different IP
addresses within a time window too short for a person to physically travel between
those locations. It indicates either stolen credentials or a compromised account.

## Analogy

If your bank card is used in Frankfurt at 10:00 and then in Cape Town at 10:05,
the bank flags it immediately. No person can be in both places within 5 minutes.
The same logic applies to network logins.

## What We Built

A second detection pass that groups all login events by USERNAME instead of IP
address. It then compares every unique pair of IPs for each user and alerts when
the same user appears from two different locations within 60 seconds.

## Detection Logic

- Group all events by username across all log files
- Sort events by timestamp
- For each user compare every pair of events from different IPs
- If the time gap between two different IPs is within 60 seconds → alert
- Track alerted IP pairs using a set to prevent duplicate alerts

## Key Terms

| Term                | Definition                                                                           |
| ------------------- | ------------------------------------------------------------------------------------ |
| Impossible Travel   | Same user appearing from two locations in an impossibly short time                   |
| Credential Theft    | An attacker using stolen login credentials to access an account                      |
| Lateral Movement    | An attacker moving from one system to another inside a network                       |
| Correlation         | Linking related events across multiple data points to find patterns                  |
| Alert Deduplication | Suppressing repeated alerts for the same underlying event                            |
| IP Pair             | A unique combination of two IP addresses used to track impossible travel             |
| set()               | A Python data structure that stores only unique values — used to track alerted pairs |

## Key Commands / Tools

```python
# Group events by username
user_activity[user].append({"ip": ip, "time": time, "event": event})

# Sort events by time
events.sort(key=lambda x: x["time"])

# Track alerted pairs to prevent duplicates
alerted_pairs = set()
pair = tuple(sorted([ip1, ip2]))
if pair in alerted_pairs:
    continue
alerted_pairs.add(pair)

# Time gap between two events
diff = (time2 - time1).total_seconds()
if diff <= 60:
    # Impossible travel detected
```

## Credential Stuffing vs Impossible Travel

| Attack              | What it looks like                              |
| ------------------- | ----------------------------------------------- |
| Brute Force         | One IP, one user, many attempts fast            |
| Credential Stuffing | One IP, many different usernames, burst pattern |
| Impossible Travel   | One username, multiple IPs, short time gap      |

## Real World Context

In enterprise environments impossible travel detection uses geolocation data to
calculate the physical distance between two IPs and compares it against the time
gap. If a user cannot have physically travelled that distance, the account is
flagged and often automatically suspended pending investigation.

## Exam Tip

Impossible travel detection groups by USERNAME not IP. This is the key difference
from brute force detection. The same log data produces different insights depending
on how you group and correlate it.
