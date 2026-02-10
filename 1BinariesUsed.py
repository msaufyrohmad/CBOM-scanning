#!/usr/bin/env python3

import os
import platform
import subprocess
import csv
import re
import psutil

from crypto_rules import CRYPTO_RULES
from crypto_rules import CRYPTO_LIB_PATTERNS

# ==========================================================
# OS DETECTION
# ==========================================================

def detect_os():
    if os.name == "nt" or platform.system().lower().startswith("win"):
        return "windows"
    return "unix"

OS_TYPE = detect_os()

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

def list_running_binaries():
    binaries = set()

    if OS_TYPE == "unix":
        proc_dir = "/proc"
        for pid in os.listdir(proc_dir):
            if not pid.isdigit():
                continue
            exe_path = os.path.join(proc_dir, pid, "exe")
            try:
                real_exe = os.readlink(exe_path)
                if os.path.isfile(real_exe) and os.access(real_exe, os.X_OK):
                    binaries.add(real_exe)
            except Exception:
                continue

    else:  # Windows
        # Get PIDs
        tasklist = run_cmd("tasklist /FO CSV /NH")
        for line in tasklist.splitlines():
            if not line.strip():
                continue
            exe_name = line.split('","')[0].strip('"')

            # Resolve full path
            wmic = run_cmd(f'wmic process where name="{exe_name}" get ExecutablePath /value')
            for l in wmic.splitlines():
                if l.lower().startswith("executablepath="):
                    path = l.split("=", 1)[1].strip()
                    if os.path.isfile(path):
                        binaries.add(path)

    print(len(binaries)," detected")
    return sorted(binaries)
# ==========================================================
# DEPENDENCY SCANNING
# ==========================================================

def get_crypto_deps(binary):
    deps = list()

    if OS_TYPE == "unix":
        out = run_cmd(["ldd", binary])
    else:
        out = run_cmd(f'dumpbin /imports "{binary}"')

    for line in out.splitlines():
        for lib in CRYPTO_LIB_PATTERNS:
            if lib.lower() in line.lower():
                deps.append(lib)

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
        return

    try:
        # Run ldd and capture output
        result = subprocess.check_output(['ldd', binary_path], stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError:
        print(f"Error: Could not run ldd on {binary_path}. Is it a valid binary?")
        return

    system_libs = []
    third_party_libs = []

    # Standard system paths
    system_paths = ['/lib', '/usr/lib', '/lib64']

    for line in result.splitlines():
        if "=>" in line:
            parts = line.split("=>")
            lib_name = parts[0].strip()
            lib_path = parts[1].split('(')[0].strip()

            if not lib_path or lib_path == "not found":
                continue

            # Check if the path starts with a standard system directory
            is_system = any(lib_path.startswith(p) for p in system_paths)
            
            # Exclude /usr/local/lib as it is usually for third-party
            if lib_path.startswith('/usr/local/lib'):
                is_system = False

            if is_system:
                system_libs.append(lib_path)
            else:
                third_party_libs.append(lib_path)

    return third_party_libs,system_libs


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
# MAIN
# ==========================================================

def main():
    with open("binaries_used.csv", "w", newline="") as f:
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

        for binary in list_running_binaries():
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
	for binary in list_running_binaries():
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
            #for hit in hits:
            #    print(hit)

if __name__ == "__main__":
    main()
#     display()
