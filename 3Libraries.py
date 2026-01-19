#!/usr/bin/env python3

import os
import platform
import subprocess
import csv
import re

# ==========================================================
# OS DETECTION
# ==========================================================

def detect_os():
    if os.name == "nt" or platform.system().lower().startswith("win"):
        return "windows"
    return "unix"

OS_TYPE = detect_os()

# ==========================================================
# CRYPTO DETECTION RULES (UNCHANGED)
# ==========================================================

CRYPTO_RULES = {

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

    "AES-GCM": {
        "primitive": "aead",
        "cyclonedx_family": "AES-GCM"
    },

    "CHACHA20-POLY1305": {
        "primitive": "aead",
        "cyclonedx_family": "ChaCha20-Poly1305"
    },

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

    "HMAC": {
        "primitive": "mac",
        "hashes": ["SHA-256", "SHA-384", "SHA-512"],
        "cyclonedx_family": "HMAC"
    },

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

# ==========================================================
# LIBRARY SEARCH PATHS (OS-SPECIFIC)
# ==========================================================

if OS_TYPE == "unix":
    LIB_DIRS = [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib"
    ]
    LIB_EXTS = (".so", ".a", ".la")
else:
    LIB_DIRS = [
        os.environ.get("SystemRoot", "C:\\Windows") + "\\System32",
        os.environ.get("SystemRoot", "C:\\Windows") + "\\SysWOW64"
    ]
    LIB_EXTS = (".dll", ".lib")

# ==========================================================
# HELPERS
# ==========================================================

def run_cmd(cmd):
    try:
        if OS_TYPE == "windows":
            return subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, shell=True
            ).decode(errors="ignore")
        else:
            return subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
    except Exception:
        return ""

def is_library(path):
    if OS_TYPE == "windows":
        return path.lower().endswith(LIB_EXTS)
    return path.endswith(LIB_EXTS) or ".so." in path

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

# ==========================================================
# DEPENDENCY SCANNING
# ==========================================================

def get_crypto_deps(lib):
    libs = set()

    if OS_TYPE == "unix":
        if not lib.endswith(".so") and ".so." not in lib:
            return "not-applicable"
        out = run_cmd(["ldd", lib])
    else:
        out = run_cmd(f'dumpbin /imports "{lib}"')

    for line in out.splitlines():
        for pat in CRYPTO_LIB_PATTERNS:
            if pat.lower() in line.lower():
                libs.add(pat)

    return ",".join(sorted(libs)) if libs else "none"

# ==========================================================
# CRYPTO DETECTION (STRINGS-BASED)
# ==========================================================

def detect_crypto(lib):
    results = []
    strings_out = run_cmd(
        ["strings", lib] if OS_TYPE == "unix"
        else f'strings "{lib}"'
    )

    for alg, meta in CRYPTO_RULES.items():
        if alg in strings_out:
            key_size = "unknown"
            for size in meta.get("key_lengths", []):
                if re.search(rf"{alg}[-_ ]?{size}", strings_out):
                    key_size = size
                    break
            results.append((alg, meta["primitive"], key_size))

    return results

# ==========================================================
# MAIN
# ==========================================================

def main():
    with open("library.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "library",
            "os_type",
            "library_type",
            "crypto_dependency",
            "algorithm",
            "primitive",
            "key_size",
            "detection_method"
        ])

        for lib in find_libraries():
            print(lib)
            if lib.lower().endswith(".a"):
                lib_type = "static"
            elif lib.lower().endswith(".la"):
                lib_type = "libtool"
            elif lib.lower().endswith(".lib"):
                lib_type = "import-lib"
            else:
                lib_type = "shared"

            crypto_deps = get_crypto_deps(lib)
            crypto_hits = detect_crypto(lib)

            if not crypto_hits:
                writer.writerow([
                    lib,
                    OS_TYPE,
                    lib_type,
                    crypto_deps,
                    "unknown",
                    "unknown",
                    "unknown",
                    "dependency-only" if crypto_deps != "none" else "static-string"
                ])
            else:
                for alg, primitive, key_size in crypto_hits:
                    writer.writerow([
                        lib,
                        OS_TYPE,
                        lib_type,
                        crypto_deps,
                        alg,
                        primitive,
                        key_size,
                        "dependency + strings"
                    ])

    print("[+] CSV generated: library_crypto_inventory.csv")

if __name__ == "__main__":
    main()
