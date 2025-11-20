#!/usr/bin/env python3
import re
import argparse
import csv
import math

BREACHED_PATTERNS = [
    "123456", "password", "qwerty", "111111", "admin", "letmein", "welcome"
]

def password_entropy(password):
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"[!@#$%^&*(),.?":{}|<>]", password): charset += 32
    if charset == 0:
        return 0
    entropy = len(password) * math.log2(charset)
    return round(entropy, 2)

def check_strength(password):
    issues = []

    if len(password) < 8:
        issues.append("Too short (minimum 8 characters recommended)")
    if not re.search(r"[A-Z]", password):
        issues.append("Missing uppercase letter")
    if not re.search(r"[a-z]", password):
        issues.append("Missing lowercase letter")
    if not re.search(r"[0-9]", password):
        issues.append("Missing number")
    if not re.search(r"[!@#$%^&*(),.?":{}|<>]", password):
        issues.append("Missing special character")

    breached = any(pattern in password.lower() for pattern in BREACHED_PATTERNS)
    if breached:
        issues.append("Password matches a commonly breached pattern")

    entropy_value = password_entropy(password)

    return issues, entropy_value

def generate_report(password, issues, entropy, output):
    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Password", "Entropy", "Issues"])
        writer.writerow([password, entropy, "; ".join(issues) if issues else "None"])
    print(f"[+] Report saved to {output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Password Strength & Breach Checker")
    parser.add_argument("--password", required=True, help="Password to check")
    parser.add_argument("--output", default="password_report.csv", help="Output CSV file")
    args = parser.parse_args()

    issues, entropy = check_strength(args.password)

    print("\n=== Password Strength Report ===")
    print(f"Password: {args.password}")
    print(f"Entropy: {entropy}")
    if issues:
        print("Issues:")
        for item in issues:
            print(f"- {item}")
    else:
        print("No major issues. Password looks strong!")

    generate_report(args.password, issues, entropy, args.output)
