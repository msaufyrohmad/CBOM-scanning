#!/usr/bin/env python3

import os
import platform
import subprocess
import csv
import re
import psutil

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
# BINARY STATE
# =========================================================

def check_binary_state(file_path):
    """ 
    Differentiates the state of a binary: In Use, In Transit, or At Rest.
    """
    if not os.path.exists(file_path):
        return "File does not exist on disk."

    abs_path = os.path.abspath(file_path)
    file_name = os.path.basename(file_path)

    # 1. CHECK FOR "IN USE" (Process Table)
    # We look for any process whose executable path matches our binary
    for proc in psutil.process_iter(['exe', 'name']):
        try:
            if proc.info['exe'] and os.path.abspath(proc.info['exe']) == abs_path:
                return f"STATE: IN USE (Running as PID {proc.pid})"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # 2. CHECK FOR "IN TRANSIT" (Network/Open Handles)
    # We check if a network-related process (wget, scp, curl, rsync) has a handle on this file
    transit_tools = ['wget', 'scp', 'rsync', 'curl', 'sftp-server', 'transmission']
    for proc in psutil.process_iter(['name', 'open_files']):
        try:
            # Check if it's a known transfer tool
            if proc.info['name'] in transit_tools:
                files = proc.open_files()
                if files:
                    for f in files:
                        if os.path.abspath(f.path) == abs_path:
                            return f"STATE: IN TRANSIT (Being moved by {proc.info['name']})"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # 3. CHECK FOR "AT REST" (Default)
    # If it's on disk but not in the process table or being handled by a transfer tool
    return "STATE: AT REST (Static on disk)"





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
# LIBRARY CLASSIFICATIONS
# ==========================================================

def classify_libraries(binary_path):
    if not os.path.exists(binary_path):
        print(f"Error: File '{binary_path}' not found.")
        return [], []

    # --- STEP 1: VALIDATE IF C/C++ BINARY (ELF CHECK) ---
    # We check the first 4 bytes for the ELF magic number: \x7fELF
    try:
        with open(binary_path, 'rb') as f:
            magic = f.read(4)
            if magic != b'\x7fELF':
                print(f"Skipping: {binary_path} is not a compiled C/C++ ELF binary (likely a script or data).")
                return [], []
    except Exception as e:
        print(f"Error reading file: {e}")
        return [], []

    # --- STEP 2: RUN LDD ANALYSIS ---
    try:
        result = subprocess.check_output(['ldd', binary_path], stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError:
        # This often happens if the binary is for a different architecture (e.g., ARM binary on x86)
        print(f"Error: ldd failed on {binary_path}. Architecture mismatch or corrupted binary.")
        return [], []

    system_libs = []
    third_party_libs = []
    system_paths = ['/lib', '/usr/lib', '/lib64']

    for line in result.splitlines():
        if "=>" in line:
            parts = line.split("=>")
            lib_name = parts[0].strip()
            lib_path = parts[1].split('(')[0].strip()

            if not lib_path or lib_path == "not found":
                continue

            is_system = any(lib_path.startswith(p) for p in system_paths)
            
            # Refine third-party check
            if lib_path.startswith('/usr/local/lib'):
                is_system = False

            if is_system:
                system_libs.append(lib_path)
            else:
                third_party_libs.append(lib_path)

    return third_party_libs, system_libs

# ===================================================================
# GUESS PRORGRAMMING LANGUAGE
# ==================================================================

def guess_language(binary_path):
    signatures = { 
        "Go": ["go.runtime", "runtime.gopanic"],
        "Rust": ["rustc/", "rust_panic"],
        "Python": ["py_runmain", "PyZipFile", "_PYI"],
        "C++": ["GLIBCXX", "std::"],
        "Java": ["JNI_CreateJavaVM", "java/lang/Object"]
    }   

    try:
        # Get strings from the binary
        output = subprocess.check_output(['strings', binary_path]).decode(errors='ignore')
    
        for lang, sigs in signatures.items():
            if any(sig in output for sig in sigs):
                return lang
    
        return "C" 
    except Exception as e:
        return f"Error: {e}"


# ==========================================================
# MAIN NEW
# =========================================================
def main():
    with open("binaries_at_disk.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "binary",
            "os_type",
            "language",
	    "modules/libraries",
	    "third party libraries",
            "primitive",
            "algorithm",
            "crypto_library",
            "key_length",
            "parameters"
        ])

        for binary in list_binaries():
            print(binary)
            language=guess_language(binary)
            third_party,system=classify_libraries(binary)
            libs = get_crypto_deps(binary)
            if libs == "none":
                continue

            hits = detect_crypto(binary)
            if not hits:
                writer.writerow([
                    binary,
                    OS_TYPE,
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                    libs,
                    "unknown",
                    "none"
                ])
                continue

            for hit in hits:
                params = hit.get("parameters", {})
                key_len = params.pop("keyLength", "unknown")
                param_str = "; ".join(f"{k}={v}" for k, v in params.items()) or "none"

                writer.writerow([
                    binary,
                    OS_TYPE,
                    language,
                    system,
                    third_party,
                    hit["primitive"],
                    hit["algorithm"],
                    libs,
                    key_len,
                    param_str
                ])

def display():
	for binary in list_binaries():
            language=guess_language(binary)
            third_party,system=classify_libraries(binary)
            libs = get_crypto_deps(binary)
            state = check_binary_state(binary)
            if libs == "none":
                continue
            print("Binary : ", binary)
            print("Language : ", language)
            print("State : ", state)
            print("System Library : ", system)
            print("Third Party Library : ",third_party)
            print("Crypto Library : ",libs)
            hits = detect_crypto(binary)
            for hit in hits:
                print(hit)



if __name__ == "__main__":
    main()
#    display()
