#!/usr/bin/env python3

import os
import subprocess
import csv
import re

# === Crypto detection rules ===

CRYPTO_RULES = {

    # === Symmetric Ciphers ===
    "AES": {
        "primitive": "block-cipher",
        "modes": ["ECB", "CBC", "CTR", "GCM", "CCM", "XTS"],
        "key_lengths": [128, 192, 256],
        "cyclonedx_family": "AES"
    },

    "CHACHA20": {
        "primitive": "stream-cipher",
        "cyclonedx_family": "ChaCha20"
    },

    # === AEAD ===
    "AES-GCM": {
        "primitive": "aead",
        "cyclonedx_family": "AES-GCM"
    },

    "CHACHA20-POLY1305": {
        "primitive": "aead",
        "cyclonedx_family": "ChaCha20-Poly1305"
    },

    # === Hash Functions ===
    "SHA-1": {
        "primitive": "hash",
        "cyclonedx_family": "SHA-1"
    },

    "SHA-256": {
        "primitive": "hash",
        "cyclonedx_family": "SHA-256"
    },

    "SHA-384": {
        "primitive": "hash",
        "cyclonedx_family": "SHA-384"
    },

    "SHA-512": {
        "primitive": "hash",
        "cyclonedx_family": "SHA-512"
    },

    "MD5": {
        "primitive": "hash",
        "cyclonedx_family": "MD5",
        "deprecated": True
    },

    # === Public Key / Asymmetric ===
    "RSA": {
        "primitive": "public-key",
        "key_lengths": [1024, 2048, 3072, 4096],
        "padding": ["PKCS1v1.5", "PSS"],
        "cyclonedx_family": "RSA"
    },

    "ECDSA": {
        "primitive": "digital-signature",
        "curves": ["P-256", "P-384", "P-521", "secp256k1"],
        "hashes": ["SHA-256", "SHA-384", "SHA-512"],
        "cyclonedx_family": "ECDSA"
    },

    "ECDH": {
        "primitive": "key-agreement",
        "curves": ["P-256", "P-384", "X25519", "X448"],
        "cyclonedx_family": "ECDH"
    },

    "ED25519": {
        "primitive": "digital-signature",
        "cyclonedx_family": "Ed25519"
    },

    # === MAC ===
    "HMAC": {
        "primitive": "mac",
        "hashes": ["SHA-256", "SHA-384", "SHA-512"],
        "cyclonedx_family": "HMAC"
    },

    # === Protocols ===
    "TLS": {
        "primitive": "protocol",
        "versions": ["1.0", "1.1", "1.2", "1.3"],
        "cyclonedx_family": "TLS"
    },

    "SSL": {
        "primitive": "protocol",
        "versions": ["2.0", "3.0"],
        "deprecated": True,
        "cyclonedx_family": "SSL"
    }
}





CRYPTO_LIB_PATTERNS = [
    "libcrypto",
    "libssl",
    "mbedtls",
    "wolfssl",
    "boringssl",
    "libgcrypt",
    "libsodium",
    "nettle"
]

# === Helpers ===
def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
    except Exception:
        return ""

def is_executable(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)

def get_path_executables():
    """
    Get all unique executables resolved from PATH
    """
    exes = set()
    for d in os.environ.get("PATH", "").split(":"):
        if os.path.isdir(d):
            for f in os.listdir(d):
                full = os.path.join(d, f)
                if is_executable(full):
                    try:
                        exes.add(os.path.realpath(full))
                    except Exception:
                        pass
    return sorted(exes)

def get_ldd_crypto_libs(binary):
    libs = set()
    out = run_cmd(["ldd", binary])
    for line in out.splitlines():
        for lib in CRYPTO_LIB_PATTERNS:
            if lib.lower() in line.lower():
                libs.add(lib)
    return ",".join(sorted(libs)) if libs else "none"

def detect_crypto(binary):
    results = []
    strings_out = run_cmd(["strings", binary])

    for alg, meta in CRYPTO_RULES.items():
        if alg in strings_out:
            key_size = "unknown"
            if "key_sizes" in meta:
                for size in meta["key_sizes"]:
                    if re.search(rf"{alg}[-_ ]?{size}", strings_out):
                        key_size = size

            results.append((alg, meta["primitive"], key_size))

    return results

# === Main ===
def main():
    with open("path_crypto_inventory.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "binary",
            "crypto_library",
            "algorithm",
            "primitive",
            "key_size",
            "detection_method"
        ])

        for binary in get_path_executables():
            crypto_libs = get_ldd_crypto_libs(binary)
            if crypto_libs == "none":
                continue

            crypto_hits = detect_crypto(binary)

            if not crypto_hits:
                writer.writerow([
                    binary,
                    crypto_libs,
                    "unknown",
                    "unknown",
                    "unknown",
                    "ldd-only"
                ])
            else:
                for alg, primitive, key_size in crypto_hits:
                    writer.writerow([
                        binary,
                        crypto_libs,
                        alg,
                        primitive,
                        key_size,
                        "ldd + static-string"
                    ])

    print("[+] CSV generated: path_crypto_inventory.csv")

if __name__ == "__main__":
    main()

