import os
import re

# Keywords that usually indicate amount manipulation
AMOUNT_KEYWORDS = [
    r"\bAmount\b",
    r"\bPrice\b",
    r"\bTotal\b",
    r"\bFinalAmount\b",
    r"\bPayable\b",
    r"\bDiscount\b",
    r"\bTax\b"
]

# Patterns where request data is directly used
DANGEROUS_PATTERNS = [
    r"=\s*req\.(Amount|Price|Total|FinalAmount|Discount|Tax)",
    r"=\s*request\.(Amount|Price|Total|FinalAmount|Discount|Tax)",
    r"=\s*model\.(Amount|Price|Total|FinalAmount|Discount|Tax)"
]

def scan_file(file_path):
    findings = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for i, line in enumerate(lines, start=1):
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, line):
                findings.append((i, line.strip()))
    return findings


def scan_directory(directory):
    print("\n🔍 Scanning for Amount Manipulation vulnerabilities...\n")

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".cs"):
                file_path = os.path.join(root, file)
                results = scan_file(file_path)
                if results:
                    print(f"🚨 Potential issue in: {file_path}")
                    for line_no, code in results:
                        print(f"   Line {line_no}: {code}")
                    print("-" * 60)


if __name__ == "__main__":
    target_directory = input("Enter path to C# source code: ").strip()
    scan_directory(target_directory)
