#!/usr/bin/env python3
"""
Cross-platform Crypto Process Scanner
Detects crypto usage, primitives, algorithms, key sizes, functions
Linux + Windows
"""

import psutil
import platform
import csv
import re
from datetime import datetime

OUTPUT_CSV = "binaries_used.csv"
OS_TYPE = platform.system().lower()

# -----------------------------
# Crypto knowledge base
# -----------------------------

CRYPTO_RULES = {
    "AES": {
        "primitive": "block-cipher",
        "key_sizes": ["128", "192", "256"],
        "patterns": [r"aes[-_]?(\d{3})?", r"aesgcm", r"evp_aes"]
    },
    "ChaCha20": {
        "primitive": "stream-cipher",
        "key_sizes": ["256"],
        "patterns": [r"chacha20", r"poly1305"]
    },
    "RSA": {
        "primitive": "public-key",
        "key_sizes": ["1024", "2048", "3072", "4096"],
        "patterns": [r"rsa[-_]?(\d{4})?", r"rsassa"]
    },
    "ECC": {
        "primitive": "public-key",
        "key_sizes": ["256", "384", "521"],
        "patterns": [r"ecdsa", r"ecdh", r"curve25519", r"secp\d+"]
    },
    "SHA": {
        "primitive": "hash",
        "key_sizes": ["1", "224", "256", "384", "512"],
        "patterns": [r"sha[-_]?(\d{1,3})"]
    },
    "HMAC": {
        "primitive": "mac",
        "key_sizes": [],
        "patterns": [r"hmac"]
    }
}

FUNCTION_HINTS = {
    "openssl": "OpenSSL EVP",
    "libcrypto": "OpenSSL libcrypto",
    "libssl": "OpenSSL TLS",
    "bcrypt": "Windows CNG (bcrypt)",
    "ncrypt": "Windows CNG (ncrypt)",
    "ssh": "SSH crypto subsystem",
    "ipsec": "IPsec / IKE",
}

PROTOCOL_HINTS = {
    "https": "TLS",
    "ssl": "TLS",
    "tls": "TLS",
    "ssh": "SSH",
    "ipsec": "IPsec",
    "ike": "IPsec",
    "openvpn": "VPN",
}

CRYPTO_LIBS_LINUX = [
    "libssl", "libcrypto", "libgnutls",
    "libmbedtls", "libwolfssl", "libgcrypt"
]

CRYPTO_LIBS_WINDOWS = [
    "libssl", "libcrypto",
    "bcrypt.dll", "ncrypt.dll", "crypt32.dll", "schannel"
]

# -----------------------------
# Detection helpers
# -----------------------------

def scan_text_for_crypto(text):
    findings = []
    for algo, meta in CRYPTO_RULES.items():
        for pat in meta["patterns"]:
            for m in re.findall(pat, text, re.IGNORECASE):
                key_size = ""
                if isinstance(m, tuple):
                    m = next((x for x in m if x.isdigit()), "")
                if isinstance(m, str) and m.isdigit():
                    key_size = m

                findings.append({
                    "algorithm": algo,
                    "primitive": meta["primitive"],
                    "key_size": key_size
                })
    return findings

def scan_loaded_libraries(proc):
    libs = []
    try:
        maps = proc.memory_maps()
        for m in maps:
            path = m.path.lower()
            candidates = CRYPTO_LIBS_WINDOWS if OS_TYPE == "windows" else CRYPTO_LIBS_LINUX
            for lib in candidates:
                if lib in path:
                    libs.append(lib)
    except Exception:
        pass
    return list(set(libs))

def detect_function(text):
    for k, v in FUNCTION_HINTS.items():
        if k in text:
            return v
    return ""

def detect_protocol(text):
    for k, v in PROTOCOL_HINTS.items():
        if k in text:
            return v
    return ""

# -----------------------------
# Main scan
# -----------------------------

def main():
    rows = []
    scan_time = datetime.utcnow().isoformat()

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            pid = proc.pid
            name = proc.info.get("name") or ""
            exe = proc.info.get("exe") or ""
            cmdline = " ".join(proc.info.get("cmdline") or [])

            search_blob = f"{name} {exe} {cmdline}".lower()

            crypto_hits = scan_text_for_crypto(search_blob)
            libs = scan_loaded_libraries(proc)

            if not crypto_hits and not libs:
                continue

            function = detect_function(search_blob + " ".join(libs))
            protocol = detect_protocol(search_blob)

            for hit in crypto_hits or [{"algorithm": "", "primitive": "", "key_size": ""}]:
                rows.append([
                    scan_time,
                    OS_TYPE,
                    pid,
                    name,
                    exe,
                    hit["algorithm"],
                    hit["primitive"],
                    hit["key_size"] or "unknown",
                    function,
                    protocol,
                    ",".join(libs),
                ])

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    # -----------------------------
    # CSV Output
    # -----------------------------

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "scan_time",
            "os",
            "pid",
            "process_name",
            "executable",
            "algorithm",
            "primitive",
            "key_size",
            "crypto_function",
            "protocol",
            "crypto_libraries",
        ])
        writer.writerows(rows)

    print(f"[+] Scan completed")
    print(f"[+] Entries: {len(rows)}")
    print(f"[+] Output: {OUTPUT_CSV}")

# -----------------------------
if __name__ == "__main__":
    main()
