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
# CRYPTO RULES (CycloneDX-aligned)
# ==========================================================

CRYPTO_RULES = {

    "AES": {
        "algorithmProperties": {
            "primitive": "block-cipher",
            "algorithm": "AES",
            "modes": ["ECB", "CBC", "CTR", "GCM", "CCM", "XTS"],
            "keyLengths": [128, 192, 256]
        }
    },

    "CHACHA20": {
        "algorithmProperties": {
            "primitive": "stream-cipher",
            "algorithm": "ChaCha20"
        }
    },

    "AES-GCM": {
        "algorithmProperties": {
            "primitive": "aead",
            "algorithm": "AES",
            "mode": "GCM"
        }
    },

    "CHACHA20-POLY1305": {
        "algorithmProperties": {
            "primitive": "aead",
            "algorithm": "ChaCha20",
            "mac": "Poly1305"
        }
    },

    "SHA-1": {
        "algorithmProperties": {
            "primitive": "hash-function",
            "algorithm": "SHA-1",
            "deprecated": True
        }
    },

    "SHA-256": {
        "algorithmProperties": {
            "primitive": "hash-function",
            "algorithm": "SHA-256"
        }
    },

    "SHA-384": {
        "algorithmProperties": {
            "primitive": "hash-function",
            "algorithm": "SHA-384"
        }
    },

    "SHA-512": {
        "algorithmProperties": {
            "primitive": "hash-function",
            "algorithm": "SHA-512"
        }
    },

    "MD5": {
        "algorithmProperties": {
            "primitive": "hash-function",
            "algorithm": "MD5",
            "deprecated": True
        }
    },

    "RSA": {
        "algorithmProperties": {
            "primitive": "public-key-encryption",
            "algorithm": "RSA",
            "keyLengths": [1024, 2048, 3072, 4096]
        }
    },

    "ECDSA": {
        "algorithmProperties": {
            "primitive": "digital-signature",
            "algorithm": "ECDSA",
            "curves": ["P-256", "P-384", "P-521", "secp256k1"]
        }
    },

    "ECDH": {
        "algorithmProperties": {
            "primitive": "key-agreement",
            "algorithm": "ECDH",
            "curves": ["P-256", "P-384", "X25519", "X448"]
        }
    },

    "ED25519": {
        "algorithmProperties": {
            "primitive": "digital-signature",
            "algorithm": "Ed25519"
        }
    },

    "HMAC": {
        "algorithmProperties": {
            "primitive": "mac",
            "algorithm": "HMAC",
            "hashFunctions": ["SHA-256", "SHA-384", "SHA-512"]
        }
    },

    "TLS": {
        "protocolProperties": {
            "protocolType": "tls",
            "versions": ["1.0", "1.1", "1.2", "1.3"]
        }
    }
}

CRYPTO_LIB_PATTERNS = [
    "libcrypto",
    "libssl",
    "mbedtls",
    "wolfssl",
    "boringssl",
    "libsodium",
    "libgcrypt",
    "nettle"
]

# ==========================================================
# COMMAND EXECUTION
# ==========================================================

def run_cmd(cmd):
    try:
        if OS_TYPE == "windows":
            return subprocess.check_output(
                cmd,
                stderr=subprocess.DEVNULL,
                shell=True
            ).decode(errors="ignore")
        else:
            return subprocess.check_output(
                cmd,
                stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
    except Exception:
        return ""

# ==========================================================
# EXECUTABLE DISCOVERY
# ==========================================================

def is_executable(path):
    if OS_TYPE == "windows":
        return os.path.isfile(path) and path.lower().endswith(".exe")
    return os.path.isfile(path) and os.access(path, os.X_OK)

def list_binaries():
    binaries = set()
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if os.path.isdir(d):
            for f in os.listdir(d):
                p = os.path.join(d, f)
                if is_executable(p):
                    binaries.add(p)
    return sorted(binaries)

# ==========================================================
# DEPENDENCY SCANNING
# ==========================================================

def get_crypto_deps(binary):
    deps = set()

    if OS_TYPE == "unix":
        out = run_cmd(["ldd", binary])
    else:
        out = run_cmd(f'dumpbin /imports "{binary}"')

    for line in out.splitlines():
        for lib in CRYPTO_LIB_PATTERNS:
            if lib.lower() in line.lower():
                deps.add(lib)

    return ",".join(sorted(deps)) if deps else "none"

# ==========================================================
# CRYPTO DETECTION
# ==========================================================

def detect_crypto(binary):
    results = []

    if OS_TYPE == "unix":
        strings_out = run_cmd(["strings", binary]).lower()
        symbols_out = run_cmd(["nm", "-D", binary]).lower()
        deps_out = run_cmd(["ldd", binary]).lower()
    else:
        strings_out = run_cmd(f'strings "{binary}"').lower()
        symbols_out = run_cmd(f'dumpbin /symbols "{binary}"').lower()
        deps_out = run_cmd(f'dumpbin /imports "{binary}"').lower()

    for name, meta in CRYPTO_RULES.items():
        algo = meta.get("algorithmProperties", {})
        proto = meta.get("protocolProperties", {})

        if name.lower() not in strings_out and name.lower() not in symbols_out:
            continue

        entry = {
            "algorithm": algo.get("algorithm", name),
            "primitive": algo.get("primitive", proto.get("protocolType", "unknown")),
            "parameters": {},
            "confidence": "low",
            "detection_source": []
        }

        for size in algo.get("keyLengths", []):
            if f"{size}" in strings_out:
                entry["parameters"]["keyLength"] = size
                entry["confidence"] = "medium"
                entry["detection_source"].append("string")
                break

        for mode in algo.get("modes", []):
            if mode.lower() in strings_out:
                entry["parameters"]["mode"] = mode
                entry["detection_source"].append("string")
                break

        for curve in algo.get("curves", []):
            if curve.lower() in strings_out:
                entry["parameters"]["curve"] = curve
                entry["confidence"] = "medium"
                entry["detection_source"].append("string")
                break

        for h in algo.get("hashFunctions", []):
            if h.lower() in strings_out:
                entry["parameters"]["hash"] = h
                entry["detection_source"].append("string")
                break

        for v in proto.get("versions", []):
            if v in strings_out:
                entry["parameters"]["version"] = v
                entry["detection_source"].append("string")
                break

        if any(lib in deps_out for lib in ["libcrypto", "libssl"]):
            entry["detection_source"].append("crypto-library")
            entry["confidence"] = "medium"

        if algo.get("deprecated"):
            entry["deprecated"] = True

        results.append(entry)

    return results

# ==========================================================
# USAGE CLASSIFICATION
# ==========================================================

def classify_algorithm_usage(hit):
    src = set(hit.get("detection_source", []))
    if "symbol" in src:
        return "used"
    if "crypto-library" in src:
        return "supported"
    return "unknown"

# ==========================================================
# MAIN
# ==========================================================

def main():
    with open("binary_in_path.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "binary",
            "os_type",
            "crypto_library",
            "algorithm",
            "primitive",
            "key_length",
            "parameters",
            "confidence",
            "algorithm_usage",
            "detection_source"
        ])

        for binary in list_binaries():
            print(binary)
            libs = get_crypto_deps(binary)
            if libs == "none":
                continue

            hits = detect_crypto(binary)
            if not hits:
                writer.writerow([
                    binary,
                    OS_TYPE,
                    libs,
                    "unknown",
                    "unknown",
                    "unknown",
                    "none",
                    "low",
                    "unknown",
                    "ldd/imports"
                ])
                continue

            for hit in hits:
                params = hit.get("parameters", {})
                key_len = params.pop("keyLength", "unknown")
                param_str = "; ".join(f"{k}={v}" for k, v in params.items()) or "none"

                writer.writerow([
                    binary,
                    OS_TYPE,
                    libs,
                    hit["algorithm"],
                    hit["primitive"],
                    key_len,
                    param_str,
                    hit["confidence"],
                    classify_algorithm_usage(hit),
                    ",".join(hit["detection_source"])
                ])

if __name__ == "__main__":
    main()
