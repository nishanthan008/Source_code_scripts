import os
import re

HTTP_ATTRIBUTES = [
    r"\[HttpGet",
    r"\[HttpPost",
    r"\[HttpPut",
    r"\[HttpDelete",
    r"\[HttpPatch"
]

AUTH_ATTRIBUTES = [
    r"\[Authorize",
    r"\[FilterConfig\.CustomAuthenticated"
]

DANGEROUS_PATTERNS = [
    r"IsAuthorized\s*=\s*false",
    r"\[AllowAnonymous\]"
]

def scan_file(file_path):
    findings = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        # Detect explicit authorization disable
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, line):
                findings.append((
                    i + 1,
                    "Authorization explicitly disabled",
                    line.strip()
                ))

        # Detect HTTP endpoints without Authorize
        if any(re.search(http, line) for http in HTTP_ATTRIBUTES):
            window = lines[i:i+10]
            if not any(re.search(auth, w) for w in window):
                findings.append((
                    i + 1,
                    "HTTP endpoint without authorization",
                    line.strip()
                ))

    return findings


def scan_directory(directory):
    print("\n🔍 Scanning for Broken Access Control issues...\n")

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".cs"):
                file_path = os.path.join(root, file)
                results = scan_file(file_path)

                if results:
                    print(f"🚨 File: {file_path}")
                    for line_no, issue, code in results:
                        print(f"   Line {line_no}: [{issue}]")
                        print(f"      {code}")
                    print("-" * 70)


if __name__ == "__main__":
    target_dir = input("Enter path to C# backend source code: ").strip()
    scan_directory(target_dir)
