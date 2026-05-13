import re
from datetime import datetime

log_path = "logs/offhours_login_detector.log"
report_path = f"reports/offhours_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

# Define business hours
BUSINESS_START = 8   # 08:00
BUSINESS_END = 18    # 18:00

offhours_events = []

# Step 1: Read and parse the log
with open(log_path, "r") as f:
    for line in f:
        time_match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
        user_match = re.search(r"user:(\w+)", line)
        ip_match = re.search(r"ip:([\d\.]+)", line)
        event_match = re.search(r"(LOGIN_FAILED|LOGIN_SUCCESS)", line)

        if time_match and user_match and ip_match and event_match:
            timestamp = datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S")
            user = user_match.group(1)
            ip = ip_match.group(1)
            event = event_match.group(1)
            hour = timestamp.hour

            # Check if outside business hours
            if hour < BUSINESS_START or hour >= BUSINESS_END:
                if event == "LOGIN_FAILED":
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

                offhours_events.append({
                    "timestamp": timestamp,
                    "user": user,
                    "ip": ip,
                    "event": event,
                    "hour": hour,
                    "severity": severity
                })

# Step 2: Build report
scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
report_lines = []

report_lines.append("=" * 50)
report_lines.append("       OFF-HOURS LOGIN DETECTION REPORT")
report_lines.append(f"       Scan Time      : {scan_time}")
report_lines.append(f"       Log File       : {log_path}")
report_lines.append(f"       Business Hours : {BUSINESS_START:02d}:00 - {BUSINESS_END:02d}:00")
report_lines.append("=" * 50)
report_lines.append("")

if not offhours_events:
    report_lines.append("No off-hours activity detected.")
else:
    for i, e in enumerate(offhours_events, 1):
        report_lines.append(f"[ALERT #{i}] OFF-HOURS LOGIN")
        report_lines.append(f"  Severity  : {e['severity']}")
        report_lines.append(f"  Time      : {e['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} (Hour: {e['hour']:02d}:00)")
        report_lines.append(f"  User      : {e['user']}")
        report_lines.append(f"  IP        : {e['ip']}")
        report_lines.append(f"  Event     : {e['event']}")
        report_lines.append("")

report_lines.append("=" * 50)
report_lines.append(f"  Total Off-Hours Events : {len(offhours_events)}")
report_lines.append("=" * 50)

# Step 3: Print to terminal
for line in report_lines:
    print(line)

# Step 4: Write report
with open(report_path, "w") as report_file:
    for line in report_lines:
        report_file.write(line + "\n")

print(f"\nReport saved to: {report_path}")