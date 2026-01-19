#!/usr/bin/env python3

import os
import re
import csv
import platform
from pathlib import Path

OUTPUT_CSV = "exec_script.csv"

SCRIPT_EXT = (".py", ".sh", ".pl", ".rb", ".ps1", ".bat", ".cmd")

CRYPTO_PATTERNS = {
    "AES": {
        "primitive": "block cipher",
        "patterns": [
            r"AES\.new",
            r"openssl\s+enc\s+-aes-(128|192|256)",
        ],
    },
    "RSA": {
        "primitive": "public-key",
        "patterns": [
            r"RSA\.generate\((\d+)\)",
            r"openssl\s+genrsa\s+(\d+)",
            r"ssh-keygen\s+-t\s+rsa\s+-b\s+(\d+)",
        ],
    },
    "ECC": {
        "primitive": "public-key",
        "patterns": [
            r"EllipticCurve",
            r"secp256r1",
            r"ed25519",
        ],
    },
    "SHA": {
        "primitive": "hash",
        "patterns": [
            r"hashlib\.sha(1|224|256|384|512)",
            r"openssl\s+dgst\s+-sha(1|256|512)",
        ],
    },
    "HMAC": {
        "primitive": "MAC",
        "patterns": [
            r"hmac\.new",
        ],
    },
}

# =====================================================
# OS DETECTION
# =====================================================
def detect_os():
    return platform.system().lower()

def default_scan_root():
    os_type = detect_os()
    if os_type == "windows":
        return "C:\\"
    return "/"

# =====================================================
# SCRIPT DETECTION
# =====================================================
def is_script(path):
    os_type = detect_os()

    # Windows: extension-based
    if os_type == "windows":
        return path.lower().endswith(SCRIPT_EXT)

    # Unix-like: shebang OR extension
    try:
        with open(path, "rb") as f:
            first = f.readline()
            if first.startswith(b"#!"):
                return True
    except Exception:
        pass

    return path.lower().endswith(SCRIPT_EXT)

# =====================================================
# FILE SCANNING
# =====================================================
def scan_file(path):
    try:
        text = Path(path).read_text(errors="ignore")
    except Exception:
        return []

    findings = []

    for algo, meta in CRYPTO_PATTERNS.items():
        for pat in meta["patterns"]:
            for m in re.findall(pat, text, re.IGNORECASE):
                key_size = "unknown"

                if isinstance(m, tuple):
                    for x in m:
                        if x.isdigit():
                            key_size = x
                elif isinstance(m, str) and m.isdigit():
                    key_size = m

                findings.append({
                    "algorithm": algo,
                    "primitive": meta["primitive"],
                    "function": pat,
                    "key_size": key_size,
                })

    return findings

# =====================================================
# MAIN
# =====================================================
def main(scan_root=None):
    scan_root = scan_root or default_scan_root()
    os_type = detect_os()

    print(f"[i] Detected OS: {os_type}")
    print(f"[i] Scanning root: {scan_root}")

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "script_path",
            "language",
            "algorithm",
            "primitive",
            "function_pattern",
            "key_size"
        ])

        for dirpath, _, filenames in os.walk(scan_root):
            for name in filenames:
                print(name)
                if not name.lower().endswith(SCRIPT_EXT):
                    continue

                path = os.path.join(dirpath, name)

                if not is_script(path):
                    continue

                lang = Path(name).suffix.lstrip(".") or "unknown"
                findings = scan_file(path)

                for f in findings:
                    writer.writerow([
                        path,
                        lang,
                        f["algorithm"],
                        f["primitive"],
                        f["function"],
                        f["key_size"]
                    ])

    print(f"[+] Scan complete → {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
