import re
from datetime import datetime

log_path = "logs/windows_failed_logins.log"
report_path = f"reports/winlog_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

attacks = {}

# Step 1: Read file and split into events
with open(log_path, "r", encoding="utf-16", errors="ignore") as f:
    content = f.read()

events = re.split(r"Event\[\d+\]", content)
events = [e for e in events if e.strip()]

print(f"Total events found: {len(events)}")

# Step 2: Parse each event
for event in events:
    time_match = re.search(r"Date:\s+(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})", event)
    user_match = re.search(r"Account For Which Logon Failed:.*?Account Name:\s+(\S+)", event, re.DOTALL)
    ip_match = re.search(r"Source Network Address:\s+(\S+)", event)
    reason_match = re.search(r"Failure Reason:\s+(.+)", event)

    if not (time_match and user_match and ip_match):
        continue

    timestamp = datetime.strptime(f"{time_match.group(1)} {time_match.group(2)}", "%Y-%m-%d %H:%M:%S")
    user = user_match.group(1).strip()
    ip = ip_match.group(1).strip()
    reason = reason_match.group(1).strip() if reason_match else "Unknown"

    if user == "-" or ip == "-":
        continue

    if ip not in attacks:
        attacks[ip] = {"times": [], "users": set(), "reasons": set()}

    attacks[ip]["times"].append(timestamp)
    attacks[ip]["users"].add(user)
    attacks[ip]["reasons"].add(reason)

# Step 3: Build report
scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
report_lines = []

report_lines.append("=" * 50)
report_lines.append("       WINDOWS SECURITY EVENT REPORT")
report_lines.append(f"       Scan Time : {scan_time}")
report_lines.append(f"       Log File  : {log_path}")
report_lines.append(f"       Events    : {len(events)}")
report_lines.append("=" * 50)
report_lines.append("")

alert_count = 0
monitored_count = 0

for ip, data in attacks.items():
    times = sorted(data["times"])
    users = data["users"]
    reasons = data["reasons"]
    total_attempts = len(times)
    detected = False

    for i in range(len(times) - 2):
        diff = (times[i + 2] - times[i]).total_seconds()

        if diff <= 30:
            if total_attempts >= 10:
                severity = "CRITICAL"
            elif total_attempts >= 5:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            alert_count += 1
            report_lines.append(f"[ALERT #{alert_count}] BRUTE FORCE DETECTED")
            report_lines.append(f"  Severity  : {severity}")
            report_lines.append(f"  IP        : {ip}")
            report_lines.append(f"  Users     : {', '.join(users)}")
            report_lines.append(f"  Attempts  : {total_attempts}")
            report_lines.append(f"  Window    : {diff} seconds")
            report_lines.append(f"  Reason    : {', '.join(reasons)}")
            report_lines.append("")
            detected = True
            break

    if not detected:
        monitored_count += 1
        report_lines.append(f"[MONITORED] {ip} | Users: {', '.join(users)} | Attempts: {total_attempts}")
        report_lines.append("")

report_lines.append("=" * 50)
report_lines.append(f"  Alerts    : {alert_count}")
report_lines.append(f"  Monitored : {monitored_count}")
report_lines.append(f"  Total IPs : {alert_count + monitored_count}")
report_lines.append("=" * 50)

for line in report_lines:
    print(line)

with open(report_path, "w") as report_file:
    for line in report_lines:
        report_file.write(line + "\n")

print(f"\nReport saved to: {report_path}")