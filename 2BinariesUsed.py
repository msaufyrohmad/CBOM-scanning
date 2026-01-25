#!/usr/bin/env python3

import os
import platform
import subprocess
import csv

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
    # === Symmetric Block Ciphers ===
    "AES": {
        "assetType": "algorithm",
        "algorithmProperties": {
            "primitive": "block-cipher",
            "algorithm": "AES",
            "modes": ["ECB", "CBC", "CTR", "GCM", "CCM", "XTS"],
            "keyLengths": [128, 192, 256]
        }
    },
    "3DES": {
        "assetType": "algorithm",
        "algorithmProperties": {
            "primitive": "block-cipher",
            "algorithm": "3DES",
            "keyLengths": [112, 168]
        }
    },
    "DES": {
        "assetType": "algorithm",
        "algorithmProperties": {
            "primitive": "block-cipher",
            "algorithm": "DES",
            "deprecated": True,
            "keyLengths": [56]
        }
    },
    "Blowfish": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"Blowfish"}},
    "CAST5": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"CAST5"}},
    "CAST6": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"CAST6"}},
    "RC2": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"RC2"}},
    "RC5": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"RC5"}},
    "RC6": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"RC6"}},
    "Twofish": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"Twofish"}},
    "CAMELLIA": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"CAMELLIA"}},
    "Serpent": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"Serpent"}},
    "ARIA": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"ARIA"}},

    # === Stream Ciphers ===
    "ChaCha": {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"ChaCha"}},
    "ChaCha20": {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"ChaCha20"}},
    "Salsa20": {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"Salsa20"}},
    "RABBIT": {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"RABBIT"}},
    "3GPP-XOR": {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"3GPP-XOR"}},
    "A5/1": {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"A5/1"}},
    "A5/2": {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"A5/2"}},
    "CMEA": {"assetType":"algorithm","algorithmProperties":{"primitive":"mac","algorithm":"CMEA"}},

    # === AEAD ===
    "AES-GCM": {"assetType":"algorithm","algorithmProperties":{"primitive":"aead","algorithm":"AES","mode":"GCM"}},
    "CHACHA20-POLY1305": {"assetType":"algorithm","algorithmProperties":{"primitive":"aead","algorithm":"ChaCha20","mac":"Poly1305"}},

    # === MAC ===
    "Poly1305": {"assetType":"algorithm","algorithmProperties":{"primitive":"mac","algorithm":"Poly1305"}},
    "CMAC": {"assetType":"algorithm","algorithmProperties":{"primitive":"mac","algorithm":"CMAC"}},
    "HMAC": {"assetType":"algorithm","algorithmProperties":{"primitive":"mac","algorithm":"HMAC","hashFunctions":["SHA-256","SHA-384","SHA-512"]}},

    # === Hash Functions ===
    "SHA-1": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"SHA-1","deprecated":True}},
    "SHA-2": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"SHA-2"}},
    "SHA-3": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"SHA-3"}},
    "SHA-256": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"SHA-256"}},
    "SHA-384": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"SHA-384"}},
    "SHA-512": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"SHA-512"}},
    "MD2": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"MD2"}},
    "MD4": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"MD4"}},
    "MD5": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"MD5","deprecated":True}},
    "BLAKE2": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"BLAKE2"}},
    "BLAKE3": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"BLAKE3"}},
    "RIPEMD": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"RIPEMD"}},
    "bcrypt": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"bcrypt"}},

    # === Public Key / Digital Signature ===
    "RSAES-PKCS1": {"assetType":"algorithm","algorithmProperties":{"primitive":"public-key-encryption","algorithm":"RSA","keyLengths":[1024,2048,3072,4096],"paddings":["PKCS1v1.5"]}},
    "RSAES-OAEP": {"assetType":"algorithm","algorithmProperties":{"primitive":"public-key-encryption","algorithm":"RSA","keyLengths":[1024,2048,3072,4096],"paddings":["OAEP"]}},
    "RSASSA-PKCS1": {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"RSA"}},
    "RSASSA-PSS": {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"RSA","paddings":["PSS"]}},
    "DSA": {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"DSA"}},
    "ECDSA": {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"ECDSA","curves":["P-256","P-384","P-521","secp256k1"],"hashFunctions":["SHA-256","SHA-384","SHA-512"]}},
    "EdDSA": {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"EdDSA"}},
    "ECIES": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-agreement","algorithm":"ECIES"}},
    "ECDH": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-agreement","algorithm":"ECDH","curves":["P-256","P-384","X25519","X448"]}},
    "X3DH": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-agreement","algorithm":"X3DH"}},
    "FFDH": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-agreement","algorithm":"FFDH"}},
    "ElGamal": {"assetType":"algorithm","algorithmProperties":{"primitive":"public-key-encryption","algorithm":"ElGamal"}},
    "BLS": {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"BLS"}},
    "XMSS": {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"XMSS"}},
    "ML-KEM": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-agreement","algorithm":"ML-KEM"}},
    "ML-DSA": {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"ML-DSA"}},

    # === KDF / PRF / RNG ===
    "PBKDF1": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"PBKDF1"}},
    "PBKDF2": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"PBKDF2"}},
    "PBES1": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"PBES1"}},
    "PBES2": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"PBES2"}},
    "PBMAC1": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"PBMAC1"}},
    "HKDF": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"HKDF"}},
    "SP800-108": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"SP800-108"}},
    "KMAC": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"KMAC"}},
    "Fortuna": {"assetType":"algorithm","algorithmProperties":{"primitive":"random-generator","algorithm":"Fortuna"}},
    "Yarrow": {"assetType":"algorithm","algorithmProperties":{"primitive":"random-generator","algorithm":"Yarrow"}},
    "TUAK": {"assetType":"algorithm","algorithmProperties":{"primitive":"random-generator","algorithm":"TUAK"}},
    "MILENAGE": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"MILENAGE"}},

    # === Protocols ===
    "TLS": {"assetType":"protocol","protocolProperties":{"protocolType":"tls","versions":["1.0","1.1","1.2","1.3"]}},
    "SSL": {"assetType":"protocol","protocolProperties":{"protocolType":"ssl","versions":["2.0","3.0"],"deprecated":True}},
    "IPSec": {"assetType": "protocol","protocolProperties": {"protocolType": "ipsec","versions": ["IKEv1", "IKEv2"] }},
    "SSH" : {"assetType": "protocol","protocolProperties": {"protocolType": "ssh","versions": ["1.0", "2.0"], "deprecated": True }},

    # === Others / miscellaneous default entries ===
    "IDEA": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"IDEA"}},
    "SNOW3G": {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"SNOW3G"}},
    "Skipjack": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"Skipjack"}},
    "SEED": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"SEED"}}
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
# COMMAND EXECUTION
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

# ==========================================================
# RUNNING PROCESS DISCOVERY
# ==========================================================

def list_running_binaries():
    binaries = set()

    if OS_TYPE == "unix":
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            exe = f"/proc/{pid}/exe"
            try:
                real = os.readlink(exe)
                if os.path.isfile(real) and os.access(real, os.X_OK):
                    binaries.add(real)
            except Exception:
                continue

    else:
        out = run_cmd("wmic process get ExecutablePath")
        for line in out.splitlines():
            p = line.strip()
            if p and os.path.isfile(p):
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
            if str(size) in strings_out:
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
    with open("binaries_used.csv", "w", newline="") as f:
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

        for binary in list_running_binaries():
            print(f"[+] Scanning: {binary}")

            libs = get_crypto_deps(binary)
            if libs == "none":
                continue

            hits = detect_crypto(binary)
            if not hits:
                writer.writerow([
                    binary, OS_TYPE, libs,
                    "unknown", "unknown", "unknown",
                    "none", "low", "unknown", "ldd/imports"
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
