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

LIB_DIRS = [
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib"
]

# === Helpers ===
def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
    except Exception:
        return ""

def is_library(path):
    return path.endswith((".so", ".a", ".la")) or ".so." in path

def find_libraries():
    libs = set()
    for d in LIB_DIRS:
        if os.path.isdir(d):
            for root, _, files in os.walk(d):
                for f in files:
                    full = os.path.join(root, f)
                    if is_library(full):
                        libs.add(os.path.realpath(full))
    return sorted(libs)

def get_ldd_crypto_libs(lib):
    if not lib.endswith(".so") and ".so." not in lib:
        return "not-applicable"

    libs = set()
    out = run_cmd(["ldd", lib])
    for line in out.splitlines():
        for pat in CRYPTO_LIB_PATTERNS:
            if pat.lower() in line.lower():
                libs.add(pat)

    return ",".join(sorted(libs)) if libs else "none"

def detect_crypto(lib):
    results = []
    strings_out = run_cmd(["strings", lib])

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
    with open("library_crypto_inventory.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "library",
            "library_type",
            "crypto_dependency",
            "algorithm",
            "primitive",
            "key_size",
            "detection_method"
        ])

        for lib in find_libraries():
            if lib.endswith(".a"):
                lib_type = "static"
            elif lib.endswith(".la"):
                lib_type = "libtool"
            else:
                lib_type = "shared"

            crypto_deps = get_ldd_crypto_libs(lib)
            crypto_hits = detect_crypto(lib)

            if not crypto_hits:
                writer.writerow([
                    lib,
                    lib_type,
                    crypto_deps,
                    "unknown",
                    "unknown",
                    "unknown",
                    "ldd-only" if crypto_deps != "none" else "static-string"
                ])
            else:
                for alg, primitive, key_size in crypto_hits:
                    writer.writerow([
                        lib,
                        lib_type,
                        crypto_deps,
                        alg,
                        primitive,
                        key_size,
                        "ldd + static-string"
                    ])

    print("[+] CSV generated: library_crypto_inventory.csv")

if __name__ == "__main__":
    main()

