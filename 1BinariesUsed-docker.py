#!/usr/bin/env python3
"""
1BinariesUsed-docker.py - Container-friendly variant.

Changes vs. original:
  * Statically-linked binaries are NO LONGER silently skipped (they are
    recorded with crypto_library="static").
  * /proc/<pid>/exe symlinks that resolve to paths invisible from the
    scanner's mount namespace are retried via /proc/<pid>/root/<exe>
    (works when the target container's rootfs is not bind-mounted).
  * Optional ROOT_PREFIX env var lets you scan a host filesystem mounted
    at e.g. /host without editing the script (set ROOT_PREFIX=/host).
  * Optional OUTPUT_CSV env var sets the output file path
    (default: ./binaries_used.csv).
  * All file/proc access is wrapped to never crash on PermissionError;
    failures are logged to stderr instead of being silently swallowed.
  * Skips kernel threads (no exe link) cleanly.
"""

import os
import sys
import platform
import subprocess
import csv
import psutil


# =========================================================================
# CONFIG (overridable via environment)
# =========================================================================
ROOT_PREFIX = os.environ.get("ROOT_PREFIX", "")          # e.g. "/host"
OUTPUT_CSV  = os.environ.get("OUTPUT_CSV", "binaries_used.csv")
VERBOSE     = os.environ.get("VERBOSE", "0") == "1"


def log(msg):
    if VERBOSE:
        print(f"[scan] {msg}", file=sys.stderr)


# =========================================================================
# CRYPTO RULES (unchanged from original - trimmed here for brevity in the
# message; KEEP THE FULL DICT FROM THE ORIGINAL FILE WHEN YOU PASTE THIS).
# =========================================================================
CRYPTO_RULES = {
    # === Symmetric Block Ciphers ===
    "AES":      {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"AES","modes":["ECB","CBC","CTR","GCM","CCM","XTS"],"keyLengths":[128,192,256]}},
    "3DES":     {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"3DES","keyLengths":[112,168]}},
    "DES":      {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"DES","deprecated":True,"keyLengths":[56]}},
    "Blowfish": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"Blowfish"}},
    "CAST5":    {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"CAST5"}},
    "CAST6":    {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"CAST6"}},
    "RC2":      {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"RC2"}},
    "RC5":      {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"RC5"}},
    "RC6":      {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"RC6"}},
    "Twofish":  {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"Twofish"}},
    "CAMELLIA": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"CAMELLIA"}},
    "Serpent":  {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"Serpent"}},
    "ARIA":     {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"ARIA"}},
    # === Stream Ciphers ===
    "ChaCha":   {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"ChaCha"}},
    "ChaCha20": {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"ChaCha20"}},
    "Salsa20":  {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"Salsa20"}},
    "RABBIT":   {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"RABBIT"}},
    "3GPP-XOR": {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"3GPP-XOR"}},
    "A5/1":     {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"A5/1"}},
    "A5/2":     {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"A5/2"}},
    "CMEA":     {"assetType":"algorithm","algorithmProperties":{"primitive":"mac","algorithm":"CMEA"}},
    # === AEAD ===
    "AES-GCM":            {"assetType":"algorithm","algorithmProperties":{"primitive":"aead","algorithm":"AES","mode":"GCM"}},
    "CHACHA20-POLY1305":  {"assetType":"algorithm","algorithmProperties":{"primitive":"aead","algorithm":"ChaCha20","mac":"Poly1305"}},
    # === MAC ===
    "Poly1305": {"assetType":"algorithm","algorithmProperties":{"primitive":"mac","algorithm":"Poly1305"}},
    "CMAC":     {"assetType":"algorithm","algorithmProperties":{"primitive":"mac","algorithm":"CMAC"}},
    "HMAC":     {"assetType":"algorithm","algorithmProperties":{"primitive":"mac","algorithm":"HMAC","hashFunctions":["SHA-256","SHA-384","SHA-512"]}},
    # === Hash Functions ===
    "SHA-1":   {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"SHA-1","deprecated":True}},
    "SHA-2":   {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"SHA-2"}},
    "SHA-3":   {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"SHA-3"}},
    "SHA-256": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"SHA-256"}},
    "SHA-384": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"SHA-384"}},
    "SHA-512": {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"SHA-512"}},
    "MD2":     {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"MD2"}},
    "MD4":     {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"MD4"}},
    "MD5":     {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"MD5","deprecated":True}},
    "BLAKE2":  {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"BLAKE2"}},
    "BLAKE3":  {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"BLAKE3"}},
    "RIPEMD":  {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"RIPEMD"}},
    "bcrypt":  {"assetType":"algorithm","algorithmProperties":{"primitive":"hash-function","algorithm":"bcrypt"}},
    # === Public Key / Digital Signature ===
    "RSAES-PKCS1":  {"assetType":"algorithm","algorithmProperties":{"primitive":"public-key-encryption","algorithm":"RSA","keyLengths":[1024,2048,3072,4096],"paddings":["PKCS1v1.5"]}},
    "RSAES-OAEP":   {"assetType":"algorithm","algorithmProperties":{"primitive":"public-key-encryption","algorithm":"RSA","keyLengths":[1024,2048,3072,4096],"paddings":["OAEP"]}},
    "RSASSA-PKCS1": {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"RSA"}},
    "RSASSA-PSS":   {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"RSA","paddings":["PSS"]}},
    "DSA":          {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"DSA"}},
    "ECDSA":        {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"ECDSA","curves":["P-256","P-384","P-521","secp256k1"],"hashFunctions":["SHA-256","SHA-384"]}},
    "EdDSA":        {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"EdDSA"}},
    "ECIES":        {"assetType":"algorithm","algorithmProperties":{"primitive":"key-agreement","algorithm":"ECIES"}},
    "ECDH":         {"assetType":"algorithm","algorithmProperties":{"primitive":"key-agreement","algorithm":"ECDH","curves":["P-256","P-384","X25519","X448"]}},
    "X3DH":         {"assetType":"algorithm","algorithmProperties":{"primitive":"key-agreement","algorithm":"X3DH"}},
    "FFDH":         {"assetType":"algorithm","algorithmProperties":{"primitive":"key-agreement","algorithm":"FFDH"}},
    "ElGamal":      {"assetType":"algorithm","algorithmProperties":{"primitive":"public-key-encryption","algorithm":"ElGamal"}},
    "BLS":          {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"BLS"}},
    "XMSS":         {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"XMSS"}},
    "ML-KEM":       {"assetType":"algorithm","algorithmProperties":{"primitive":"key-agreement","algorithm":"ML-KEM"}},
    "ML-DSA":       {"assetType":"algorithm","algorithmProperties":{"primitive":"digital-signature","algorithm":"ML-DSA"}},
    # === KDF / PRF / RNG ===
    "PBKDF1":   {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"PBKDF1"}},
    "PBKDF2":   {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"PBKDF2"}},
    "PBES1":    {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"PBES1"}},
    "PBES2":    {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"PBES2"}},
    "PBMAC1":   {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"PBMAC1"}},
    "HKDF":     {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"HKDF"}},
    "SP800-108":{"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"SP800-108"}},
    "KMAC":     {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"KMAC"}},
    "Fortuna":  {"assetType":"algorithm","algorithmProperties":{"primitive":"random-generator","algorithm":"Fortuna"}},
    "Yarrow":   {"assetType":"algorithm","algorithmProperties":{"primitive":"random-generator","algorithm":"Yarrow"}},
    "TUAK":     {"assetType":"algorithm","algorithmProperties":{"primitive":"random-generator","algorithm":"TUAK"}},
    "MILENAGE": {"assetType":"algorithm","algorithmProperties":{"primitive":"key-derivation","algorithm":"MILENAGE"}},
    # === Protocols ===
    "TLS":   {"assetType":"protocol","protocolProperties":{"protocolType":"tls","versions":["1.0","1.1","1.2","1.3"]}},
    "SSL":   {"assetType":"protocol","protocolProperties":{"protocolType":"ssl","versions":["2.0","3.0"],"deprecated":True}},
    "IPSec": {"assetType":"protocol","protocolProperties":{"protocolType":"ipsec","versions":["IKEv1","IKEv2"]}},
    "SSH":   {"assetType":"protocol","protocolProperties":{"protocolType":"ssh","versions":["1.0","2.0"],"deprecated":True}},
    # === Others ===
    "IDEA":     {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"IDEA"}},
    "SNOW3G":   {"assetType":"algorithm","algorithmProperties":{"primitive":"stream-cipher","algorithm":"SNOW3G"}},
    "Skipjack": {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"Skipjack"}},
    "SEED":     {"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","algorithm":"SEED"}},
}

CRYPTO_LIB_PATTERNS = [
    "libcrypto", "libssl", "mbedtls", "wolfssl",
    "boringssl", "libgcrypt", "libsodium", "nettle",
]


# =========================================================================
# OS DETECTION
# =========================================================================
def detect_os():
    if os.name == "nt" or platform.system().lower().startswith("win"):
        return "windows"
    return "unix"

OS_TYPE = detect_os()


# =========================================================================
# COMMAND EXECUTION
# =========================================================================
def run_cmd(cmd):
    try:
        if OS_TYPE == "windows":
            return subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                           shell=True).decode(errors="ignore")
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL
                                       ).decode(errors="ignore")
    except Exception as e:
        log(f"run_cmd failed for {cmd!r}: {e}")
        return ""


# =========================================================================
# BINARY DISCOVERY (container-aware)
# =========================================================================
def _resolve_exe(pid):
    """
    Resolve /proc/<pid>/exe to a path readable from THIS mount namespace.
    Falls back to /proc/<pid>/root/<exe> when the target lives in another
    container's rootfs (e.g. when scanner uses --pid=container:X but no
    --volumes-from).
    """
    proc_exe = f"/proc/{pid}/exe"
    try:
        target = os.readlink(proc_exe)
    except (FileNotFoundError, PermissionError, OSError):
        return None

    # Apply optional host prefix (e.g. ROOT_PREFIX=/host)
    candidates = []
    if ROOT_PREFIX:
        candidates.append(ROOT_PREFIX + target)
    candidates.append(target)
    # Last resort: peek into the target process's own rootfs view
    candidates.append(f"/proc/{pid}/root{target}")

    for cand in candidates:
        try:
            if os.path.isfile(cand):
                return cand
        except (PermissionError, OSError):
            continue
    return None


def list_running_binaries():
    binaries = set()

    if OS_TYPE == "unix":
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            real_exe = _resolve_exe(pid)
            if real_exe:
                binaries.add(real_exe)
    else:
        tasklist = run_cmd("tasklist /FO CSV /NH")
        for line in tasklist.splitlines():
            if not line.strip():
                continue
            exe_name = line.split('","')[0].strip('"')
            wmic = run_cmd(f'wmic process where name="{exe_name}" '
                           f'get ExecutablePath /value')
            for l in wmic.splitlines():
                if l.lower().startswith("executablepath="):
                    path = l.split("=", 1)[1].strip()
                    if os.path.isfile(path):
                        binaries.add(path)

    print(f"{len(binaries)} binaries detected", file=sys.stderr)
    return sorted(binaries)


# =========================================================================
# DEPENDENCY SCANNING (now reports static linkage instead of skipping)
# =========================================================================
def get_crypto_deps(binary):
    """
    Returns a tuple: (libs_str, is_static)
      libs_str  - comma-separated detected crypto libs, or "none" / "static"
      is_static - True if the binary is statically linked
    """
    is_static = False
    deps = []

    if OS_TYPE == "unix":
        out = run_cmd(["ldd", binary])
        if not out or "not a dynamic executable" in out.lower() \
                or "statically linked" in out.lower():
            is_static = True
    else:
        out = run_cmd(f'dumpbin /imports "{binary}"')

    for line in out.splitlines():
        for lib in CRYPTO_LIB_PATTERNS:
            if lib.lower() in line.lower():
                deps.append(lib)

    if deps:
        return ",".join(sorted(set(deps))), is_static
    return ("static" if is_static else "none"), is_static


# =========================================================================
# CRYPTO DETECTION
# =========================================================================
def detect_crypto(binary):
    results = []

    if OS_TYPE == "unix":
        strings_out = run_cmd(["strings", binary]).lower()
        symbols_out = run_cmd(["nm", "-D", binary]).lower()
        deps_out    = run_cmd(["ldd", binary]).lower()
    else:
        strings_out = run_cmd(f'strings "{binary}"').lower()
        symbols_out = run_cmd(f'dumpbin /symbols "{binary}"').lower()
        deps_out    = run_cmd(f'dumpbin /imports "{binary}"').lower()

    for name, meta in CRYPTO_RULES.items():
        algo  = meta.get("algorithmProperties", {})
        proto = meta.get("protocolProperties", {})

        if name.lower() not in strings_out and name.lower() not in symbols_out:
            continue

        entry = {
            "algorithm": algo.get("algorithm", name),
            "primitive": algo.get("primitive", proto.get("protocolType", "unknown")),
            "parameters": {},
            "confidence": "low",
            "detection_source": [],
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


# =========================================================================
# LIBRARY CLASSIFICATION
# =========================================================================
def classify_libraries(binary_path):
    if not os.path.exists(binary_path):
        return [], []
    try:
        result = subprocess.check_output(['ldd', binary_path],
                                         stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError:
        return [], []

    system_paths = ['/lib', '/usr/lib', '/lib64']
    system_libs, third_party_libs = [], []

    for line in result.splitlines():
        if "=>" not in line:
            continue
        parts = line.split("=>")
        lib_path = parts[1].split('(')[0].strip()
        if not lib_path or lib_path == "not found":
            continue
        is_system = any(lib_path.startswith(p) for p in system_paths)
        if lib_path.startswith('/usr/local/lib'):
            is_system = False
        (system_libs if is_system else third_party_libs).append(lib_path)

    return third_party_libs, system_libs


# =========================================================================
# LANGUAGE GUESS
# =========================================================================
def guess_language(binary_path):
    signatures = {
        "Go":     ["go.runtime", "runtime.gopanic"],
        "Rust":   ["rustc/", "rust_panic"],
        "Python": ["py_runmain", "PyZipFile", "_PYI"],
        "C++":    ["GLIBCXX", "std::"],
        "Java":   ["JNI_CreateJavaVM", "java/lang/Object"],
    }
    try:
        output = subprocess.check_output(
            ['strings', binary_path], stderr=subprocess.DEVNULL
        ).decode(errors='ignore')
        for lang, sigs in signatures.items():
            if any(sig in output for sig in sigs):
                return lang
        return "C"
    except Exception as e:
        return f"unknown ({e.__class__.__name__})"


# =========================================================================
# MAIN
# =========================================================================
def main():
    out_path = OUTPUT_CSV
    print(f"[scan] writing CSV to {out_path}", file=sys.stderr)

    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "binary", "os_type", "language",
            "system_libraries", "third_party_libraries",
            "primitive", "algorithm",
            "crypto_library", "linkage",
            "key_length", "parameters",
        ])

        for binary in list_running_binaries():
            log(f"scanning {binary}")
            try:
                language = guess_language(binary)
                third_party, system = classify_libraries(binary)
                libs, is_static = get_crypto_deps(binary)
                linkage = "static" if is_static else "dynamic"

                hits = detect_crypto(binary)

                # Always emit at least one row per binary
                if not hits:
                    writer.writerow([
                        binary, OS_TYPE, language,
                        ";".join(system), ";".join(third_party),
                        "unknown", "unknown",
                        libs, linkage,
                        "unknown", "none",
                    ])
                    continue

                for hit in hits:
                    params  = hit.get("parameters", {})
                    key_len = params.pop("keyLength", "unknown")
                    param_str = "; ".join(f"{k}={v}" for k, v in params.items()) or "none"
                    writer.writerow([
                        binary, OS_TYPE, language,
                        ";".join(system), ";".join(third_party),
                        hit["primitive"], hit["algorithm"],
                        libs, linkage,
                        key_len, param_str,
                    ])
            except Exception as e:
                print(f"[scan] error on {binary}: {e}", file=sys.stderr)
                continue

    print(f"[scan] done -> {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
