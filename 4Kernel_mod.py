#!/usr/bin/env python3

import subprocess
import csv
import re
import platform
import sys
from pathlib import Path

OUTPUT_CSV = "kernel_modules.csv"

# --- Crypto detection patterns ---
CRYPTO_ALGOS = {
    "AES": r"\b(aes|AES)(128|192|256)?\b",
    "DES": r"\bDES\b",
    "3DES": r"\b(3DES|DES-EDE)\b",
    "ChaCha20": r"\bChaCha20\b",
    "RSA": r"\bRSA(1024|2048|3072|4096)?\b",
    "ECC": r"\b(ECC|ECDSA|ECDH|Curve25519|secp256r1)\b",
    "SHA": r"\bSHA(1|224|256|384|512)\b",
    "HMAC": r"\bHMAC\b",
    "CMAC": r"\bCMAC\b",
}

CRYPTO_FUNCTIONS = [
    r"crypto_[a-zA-Z0-9_]+",
    r"skcipher_[a-zA-Z0-9_]+",
    r"aead_[a-zA-Z0-9_]+",
    r"hash_[a-zA-Z0-9_]+",
]

PRIMITIVES_MAP = {
    "AES": "block cipher",
    "DES": "block cipher",
    "3DES": "block cipher",
    "ChaCha20": "stream cipher",
    "RSA": "public-key",
    "ECC": "public-key",
    "SHA": "hash",
    "HMAC": "MAC",
    "CMAC": "MAC",
}

# ===============================
# OS DETECTION
# ===============================
def detect_os():
    return platform.system().lower()

# ===============================
# LINUX IMPLEMENTATION
# ===============================
def get_kernel_modules_linux():
    try:
        kernel_ver = Path("/proc/sys/kernel/osrelease").read_text().strip()
        base = f"/lib/modules/{kernel_ver}"
        cmd = ["find", base, "-type", "f", "-name", "*.ko*"]
        return subprocess.check_output(cmd, text=True).splitlines()
    except Exception as e:
        print(f"[!] Failed to locate kernel modules: {e}")
        return []

def extract_strings(path):
    try:
        return subprocess.check_output(
            ["strings", path],
            text=True,
            errors="ignore",
            stderr=subprocess.DEVNULL
        )
    except Exception:
        return ""

def detect_crypto(strings_data):
    algos = set()
    primitives = set()
    key_sizes = set()

    for algo, pattern in CRYPTO_ALGOS.items():
        matches = re.findall(pattern, strings_data, re.IGNORECASE)
        if matches:
            algos.add(algo)
            primitives.add(PRIMITIVES_MAP.get(algo, "unknown"))

            for m in matches:
                if isinstance(m, tuple):
                    for x in m:
                        if x.isdigit():
                            key_sizes.add(x)
                elif isinstance(m, str) and m.isdigit():
                    key_sizes.add(m)

    functions = set()
    for fp in CRYPTO_FUNCTIONS:
        functions.update(re.findall(fp, strings_data))

    return {
        "algorithms": ", ".join(sorted(algos)),
        "primitives": ", ".join(sorted(primitives)),
        "key_sizes": ", ".join(sorted(key_sizes)) if key_sizes else "unknown",
        "functions": ", ".join(sorted(functions)),
    }

def run_linux_scan():
    modules = get_kernel_modules_linux()

    if not modules:
        print("[!] No kernel modules found.")
        return

    with open(OUTPUT_CSV, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "module_path",
            "module_name",
            "crypto_algorithms",
            "crypto_primitives",
            "key_sizes",
            "crypto_functions"
        ])

        for mod in modules:
            strings_data = extract_strings(mod)
            crypto = detect_crypto(strings_data)

            if crypto["algorithms"]:
                writer.writerow([
                    mod,
                    Path(mod).name,
                    crypto["algorithms"],
                    crypto["primitives"],
                    crypto["key_sizes"],
                    crypto["functions"]
                ])

    print(f"[+] Linux kernel crypto scan complete")
    print(f"[+] Output saved to {OUTPUT_CSV}")

# ===============================
# WINDOWS PLACEHOLDER
# ===============================
def run_windows_scan():
    print("[!] Windows detected")
    print("[!] Linux kernel modules (.ko) do not exist on Windows")
    print("[!] This script currently supports Linux only")
    print("[i] Future extension: scan Windows drivers (.sys)")

# ===============================
# MAIN
# ===============================
def main():
    os_type = detect_os()

    print(f"[i] Detected OS: {os_type}")

    if os_type == "linux":
        run_linux_scan()
    elif os_type == "windows":
        run_windows_scan()
    else:
        print(f"[!] Unsupported OS: {os_type}")
        sys.exit(1)

if __name__ == "__main__":
    main()
