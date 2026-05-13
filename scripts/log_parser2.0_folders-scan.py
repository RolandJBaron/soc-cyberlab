import re
from datetime import datetime
import os

logs_folder = "logs"
report_path = f"reports/soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

log_files = [
    os.path.join(logs_folder, f)
    for f in os.listdir(logs_folder)
    if f.endswith(".log")
]

attacks = {}
user_activity = {}

# Step 1: Collect data per IP and per username
for file_path in log_files:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            ip_match = re.search(r"ip:([\d\.]+)", line)
            time_match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
            user_match = re.search(r"user:(\w+)", line)
            event_match = re.search(r"(LOGIN_FAILED|LOGIN_SUCCESS)", line)

            if ip_match and time_match and user_match and event_match:
                ip = ip_match.group(1)
                time = datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S")
                user = user_match.group(1)
                event = event_match.group(1)

                if event == "LOGIN_FAILED":
                    if ip not in attacks:
                        attacks[ip] = {"times": [], "users": set()}
                    attacks[ip]["times"].append(time)
                    attacks[ip]["users"].add(user)

                if user not in user_activity:
                    user_activity[user] = []
                user_activity[user].append({"ip": ip, "time": time, "event": event})

# Step 2: Build report
scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
report_lines = []

report_lines.append("=" * 50)
report_lines.append("       SOC INCIDENT REPORT")
report_lines.append(f"       Scan Time  : {scan_time}")
report_lines.append(f"       Logs Folder: {logs_folder}/")
report_lines.append(f"       Files Found: {len(log_files)}")
report_lines.append("=" * 50)
report_lines.append("")

alert_count = 0
monitored_count = 0

# Step 3: Brute force detection (by IP)
report_lines.append("--- BRUTE FORCE DETECTION ---")
report_lines.append("")

for ip, data in attacks.items():
    times = sorted(data["times"])
    users = data["users"]
    total_attempts = len(times)
    detected = False

    for i in range(len(times) - 2):
        diff = (times[i + 2] - times[i]).total_seconds()

        if diff <= 5:
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
            report_lines.append("")
            detected = True
            break

    if not detected:
        monitored_count += 1
        report_lines.append(f"[MONITORED] {ip} | Users: {', '.join(users)} | Attempts: {total_attempts}")
        report_lines.append("")

# Step 4: Impossible travel detection (by username)
report_lines.append("")
report_lines.append("--- IMPOSSIBLE TRAVEL DETECTION ---")
report_lines.append("")

for user, events in user_activity.items():
    events.sort(key=lambda x: x["time"])
    alerted_pairs = set()

    for i in range(len(events)):
        for j in range(i + 1, len(events)):
            ip1 = events[i]["ip"]
            ip2 = events[j]["ip"]
            time1 = events[i]["time"]
            time2 = events[j]["time"]

            if ip1 == ip2:
                continue

            pair = tuple(sorted([ip1, ip2]))
            if pair in alerted_pairs:
                continue

            diff = (time2 - time1).total_seconds()
            if diff <= 60:
                alerted_pairs.add(pair)
                alert_count += 1
                report_lines.append(f"[ALERT #{alert_count}] IMPOSSIBLE TRAVEL DETECTED")
                report_lines.append(f"  Severity  : HIGH")
                report_lines.append(f"  User      : {user}")
                report_lines.append(f"  IP 1      : {ip1} at {time1.strftime('%H:%M:%S')}")
                report_lines.append(f"  IP 2      : {ip2} at {time2.strftime('%H:%M:%S')}")
                report_lines.append(f"  Gap       : {diff} seconds")
                report_lines.append("")

# Step 5: Summary
report_lines.append("=" * 50)
report_lines.append(f"  Alerts    : {alert_count}")
report_lines.append(f"  Monitored : {monitored_count}")
report_lines.append(f"  Total IPs : {alert_count + monitored_count}")
report_lines.append("=" * 50)

# Step 6: Print to terminal
for line in report_lines:
    print(line)

# Step 7: Write to report file
with open(report_path, "w") as report_file:
    for line in report_lines:
        report_file.write(line + "\n")

print(f"\nReport saved to: {report_path}")