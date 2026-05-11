import re
from datetime import datetime

file_path = "logs/sample3.log"

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

print("=== TIME-BASED BRUTE FORCE DETECTOR ===\n")

# Step 2: Detect bursts and assign severity
for ip, data in attacks.items():
    times = sorted(data["times"])
    users = data["users"]
    total_attempts = len(times)
    detected = False

    for i in range(len(times) - 2):
        diff = (times[i + 2] - times[i]).total_seconds()

        if diff <= 5:
            # Severity tiering
            if total_attempts >= 10:
                severity = "CRITICAL"
            elif total_attempts >= 5:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            print(f"🚨 ATTACK DETECTED")
            print(f"   Severity  : {severity}")
            print(f"   IP        : {ip}")
            print(f"   Users     : {', '.join(users)}")
            print(f"   Attempts  : {total_attempts}")
            print(f"   Window    : {diff} seconds")
            print()
            detected = True
            break

    if not detected:
        print(f"⚠️  MONITORED : {ip} | Users: {', '.join(users)} | Attempts: {total_attempts}")

print("\n=== SCAN COMPLETE ===")
