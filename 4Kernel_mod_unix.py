#!/usr/bin/env python3

import subprocess
import csv
import re
from pathlib import Path

OUTPUT_CSV = "kernel_modules_crypto.csv"

# --- Crypto detection patterns ---
CRYPTO_ALGOS = {
    "AES": r"\b(aes|AES)(128|192|256)?\b",
    "DES": r"\bDES\b",
    "3DES": r"\b3DES|DES-EDE\b",
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

# --- Helpers ---
def get_kernel_modules():
    cmd = ["find", f"/lib/modules/{Path('/proc/version').read_text().split()[2]}", "-type", "f", "-name", "*.ko*"]
    return subprocess.check_output(cmd, text=True).splitlines()

def extract_strings(module_path):
    try:
        return subprocess.check_output(["strings", module_path], text=True, errors="ignore")
    except Exception:
        return ""

def detect_crypto(strings_data):
    algos = []
    primitives = set()
    key_sizes = set()

    for algo, pattern in CRYPTO_ALGOS.items():
        matches = re.findall(pattern, strings_data, re.IGNORECASE)
        if matches:
            algos.append(algo)
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
        "algorithms": ", ".join(sorted(set(algos))),
        "primitives": ", ".join(sorted(primitives)),
        "key_sizes": ", ".join(sorted(key_sizes)) if key_sizes else "unknown",
        "functions": ", ".join(sorted(functions)),
    }

# --- Main ---
def main():
    modules = get_kernel_modules()

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

    print(f"[+] Scan complete. Output saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()

