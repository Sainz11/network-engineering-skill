#!/usr/bin/env python3
"""Basic offline config hygiene scanner. Review findings manually; no config is changed."""
import argparse
import re
from pathlib import Path

PATTERNS = [
    ("possible password/secret", re.compile(r"(?i)(password|passwd|secret|community|api[-_]?key)\s*[:=]\s*\S+")),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("possible public IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    if not args.file.is_file():
        parser.error("file not found")
    text = args.file.read_text(errors="replace")
    findings = []
    for label, pattern in PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append((line, label))
    if findings:
        for line, label in findings:
            print(f"Line {line}: {label}; redact/review before sharing")
    else:
        print("No basic pattern matches found. This is not proof that the file is safe.")

if __name__ == "__main__":
    main()
