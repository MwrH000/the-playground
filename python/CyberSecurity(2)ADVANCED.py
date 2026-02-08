#!/usr/bin/env python3
import argparse
import hashlib
import os
import re
import socket
import json
import statistics
from datetime import datetime

# ==================================================
# BANNER & CORE
# ==================================================

def banner():
    print("=" * 60)
    print("   Cyber Security TOOLS by @MwrH000")
    print("   Defensive | CLI Toolkit")
    print("=" * 60)

def log_event(event, logfile="security_events.log"):
    with open(logfile, "a") as f:
        f.write(json.dumps(event) + "\n")

# ==================================================
# BEGINNER TOOLS
# ==================================================

def password_check(password):
    checks = {
        "Length >= 12": len(password) >= 12,
        "Uppercase": bool(re.search(r"[A-Z]", password)),
        "Lowercase": bool(re.search(r"[a-z]", password)),
        "Digit": bool(re.search(r"\d", password)),
        "Symbol": bool(re.search(r"[!@#$%^&*]", password))
    }

    score = sum(checks.values())

    print("\nPassword Analysis")
    for k, v in checks.items():
        print(f" - {k}: {'OK' if v else 'FAIL'}")

    print(f"\nScore: {score}/5")
    print("Rating:",
          "WEAK" if score <= 2 else
          "MEDIUM" if score <= 4 else
          "STRONG")

def hash_text(text):
    hashed = hashlib.sha256(text.encode()).hexdigest()
    print("SHA-256:", hashed)

def file_integrity(path):
    if not os.path.exists(path):
        print("File not found.")
        return

    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())

    print("File SHA-256:", h.hexdigest())

def log_analyzer(logfile):
    if not os.path.exists(logfile):
        print("Log file not found.")
        return

    failed = {}
    with open(logfile) as f:
        for line in f:
            if "FAILED_LOGIN" in line:
                ip = line.strip().split()[-1]
                failed[ip] = failed.get(ip, 0) + 1

    print("\nSuspicious IPs:")
    for ip, count in failed.items():
        if count >= 3:
            print(f" - {ip}: {count} failures")

# ==================================================
# INTERMEDIATE TOOLS
# ==================================================

def port_scan(host, start, end):
    print(f"\nScanning {host} (authorized targets only)")
    open_ports = []

    for port in range(start, end + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex((host, port)) == 0:
                    open_ports.append(port)
        except:
            pass

    if open_ports:
        print("Open ports:", open_ports)
    else:
        print("No open ports found.")

def rate_limit_detector(logfile, threshold):
    if not os.path.exists(logfile):
        print("Log file not found.")
        return

    attempts = 0
    with open(logfile) as f:
        for _ in f:
            attempts += 1

    if attempts >= threshold:
        print("⚠ Possible brute-force / abuse detected")
    else:
        print("Traffic looks normal")

# ==================================================
# ADVANCED TOOLS
# ==================================================

def honeypot():
    print("Honeypot simulation started. Type 'exit' to stop.")
    while True:
        cmd = input("attacker@honeypot$ ")
        if cmd.lower() == "exit":
            break

        event = {
            "type": "HONEYPOT_COMMAND",
            "command": cmd,
            "time": datetime.utcnow().isoformat()
        }
        log_event(event)
        print("Command logged.")

def anomaly_detection(values):
    if len(values) < 2:
        print("Not enough data.")
        return

    mean = statistics.mean(values)
    stdev = statistics.stdev(values)

    print("Mean:", mean)
    print("Std Dev:", stdev)

    for v in values:
        if abs(v - mean) > 2 * stdev:
            print("⚠ Anomaly detected:", v)

def siem(logfile):
    if not os.path.exists(logfile):
        print("Log file not found.")
        return

    print("\nSIEM Alerts:")
    with open(logfile) as f:
        for line in f:
            data = json.loads(line)
            if data.get("type") == "HONEYPOT_COMMAND":
                print(data)

# ==================================================
# CLI
# ==================================================

def main():
    banner()

    parser = argparse.ArgumentParser(description="Cyber Security TOOLS by @MwrH000")
    sub = parser.add_subparsers(dest="tool")

    p1 = sub.add_parser("password-check")
    p1.add_argument("--password", required=True)

    p2 = sub.add_parser("hash")
    p2.add_argument("--text", required=True)

    p3 = sub.add_parser("integrity")
    p3.add_argument("--file", required=True)

    p4 = sub.add_parser("log-analyze")
    p4.add_argument("--logfile", required=True)

    p5 = sub.add_parser("port-scan")
    p5.add_argument("--host", required=True)
    p5.add_argument("--start", type=int, default=1)
    p5.add_argument("--end", type=int, default=1024)

    p6 = sub.add_parser("rate-detect")
    p6.add_argument("--logfile", required=True)
    p6.add_argument("--threshold", type=int, default=5)

    sub.add_parser("honeypot")

    p7 = sub.add_parser("anomaly")
    p7.add_argument("--values", nargs="+", type=float, required=True)

    p8 = sub.add_parser("siem")
    p8.add_argument("--logfile", required=True)

    args = parser.parse_args()

    if args.tool == "password-check":
        password_check(args.password)
    elif args.tool == "hash":
        hash_text(args.text)
    elif args.tool == "integrity":
        file_integrity(args.file)
    elif args.tool == "log-analyze":
        log_analyzer(args.logfile)
    elif args.tool == "port-scan":
        port_scan(args.host, args.start, args.end)
    elif args.tool == "rate-detect":
        rate_limit_detector(args.logfile, args.threshold)
    elif args.tool == "honeypot":
        honeypot()
    elif args.tool == "anomaly":
        anomaly_detection(args.values)
    elif args.tool == "siem":
        siem(args.logfile)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
