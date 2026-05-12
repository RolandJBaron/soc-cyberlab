import re
from datetime import datetime

file_path = "logs/sample3.log"
report_path = "reports/soc_report.txt"

attacks = {}

# Step 1: Collect timestamps and usernames per IP
with open(file_path, "r") as file:
    for line in file:
        if "LOGIN_FAILED" in line:
            ip_match = re.search(r"ip:([\d\.]+)", line)
            time_match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
            user_match = re.search(r"user:(\w+)", line)

            if ip_match and time_match and user_match:
                ip = ip_match.group(1)
                time = datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S")
                user = user_match.group(1)

                if ip not in attacks:
                    attacks[ip] = {"times": [], "users": set()}

                attacks[ip]["times"].append(time)
                attacks[ip]["users"].add(user)

# Step 2: Detect bursts, assign severity, build report
scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
report_lines = []

report_lines.append("=" * 50)
report_lines.append("       SOC INCIDENT REPORT")
report_lines.append(f"       Scan Time : {scan_time}")
report_lines.append(f"       Log File  : {file_path}")
report_lines.append("=" * 50)
report_lines.append("")

alert_count = 0
monitored_count = 0

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

report_lines.append("=" * 50)
report_lines.append(f"  Alerts    : {alert_count}")
report_lines.append(f"  Monitored : {monitored_count}")
report_lines.append(f"  Total IPs : {alert_count + monitored_count}")
report_lines.append("=" * 50)

# Step 3: Print to terminal
for line in report_lines:
    print(line)

# Step 4: Write to report file
report_path = f"reports/soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

with open(report_path, "w") as report_file:
    for line in report_lines:
        report_file.write(line + "\n")

print(f"\nReport saved to: {report_path}")