#!/usr/bin/env python3

import psutil
import socket
import ssl
import os
import csv
import platform
from datetime import datetime

OUTPUT_CSV = "network_app.csv"

INTERPRETERS = ("python", "php", "node", "perl", "ruby", "bash", "sh")

OS_TYPE = platform.system().lower()

# ======================================================
# Protocol detection
# ======================================================
def detect_protocol(port):
    return {
        443: "TLS",
        22: "SSH",
        500: "IPsec-IKE",
        4500: "IPsec-NAT-T",
    }.get(port, "UNKNOWN")

# ======================================================
# Identify application + script
# ======================================================
def identify_application(proc):
    exe = ""
    script = ""

    try:
        exe = proc.exe()
        cmd = proc.cmdline()
    except Exception:
        return "", "", ""

    if proc.name().lower().startswith(INTERPRETERS):
        for arg in cmd[1:]:
            if os.path.isfile(arg):
                script = arg
                break

    return proc.name(), exe, script

# ======================================================
# TLS probing
# ======================================================
def parse_cipher(cipher):
    if not cipher:
        return ""

    name, proto, bits = cipher
    return f"{name} ({bits} bits)"

def probe_tls(host, port):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return f"{ssock.version()} | {parse_cipher(ssock.cipher())}"
    except Exception:
        return ""

# ======================================================
# IPsec detection (service-based)
# ======================================================
def detect_ipsec_services():
    ipsec_entries = []

    for proc in psutil.process_iter(["pid", "name", "exe"]):
        name = (proc.info["name"] or "").lower()

        if OS_TYPE == "linux":
            if name in ("charon", "pluto", "strongswan"):
                ipsec_entries.append(proc)

        elif OS_TYPE == "windows":
            if name in ("ikeext", "policyagent"):
                ipsec_entries.append(proc)

    return ipsec_entries

# ======================================================
# MAIN
# ======================================================
def main():
    rows = []
    seen = set()
    timestamp = datetime.utcnow().isoformat()

    # ================= TLS & SSH CLIENT/SERVER =================
    for conn in psutil.net_connections(kind="inet"):
        if not conn.pid:
            continue

        proto = detect_protocol(conn.raddr.port if conn.raddr else conn.laddr.port)
        if proto not in ("TLS", "SSH"):
            continue

        key = (conn.pid, conn.raddr)
        if key in seen:
            continue
        seen.add(key)

        try:
            proc = psutil.Process(conn.pid)
            pname, exe, script = identify_application(proc)

            crypto = ""
            if proto == "TLS" and conn.raddr:
                crypto = probe_tls(conn.raddr.ip, conn.raddr.port)

            rows.append([
                timestamp,
                "CLIENT" if conn.raddr else "SERVER",
                proto,
                pname,
                conn.pid,
                exe,
                script,
                conn.raddr.ip if conn.raddr else "",
                conn.raddr.port if conn.raddr else conn.laddr.port,
                crypto,
            ])
        except Exception:
            continue

    # ================= IPsec SERVICES =================
    for proc in detect_ipsec_services():
        pname, exe, _ = identify_application(proc)

        rows.append([
            timestamp,
            "SERVICE",
            "IPsec",
            pname,
            proc.pid,
            exe,
            "",
            "",
            "",
            "IKE / ESP (kernel-managed)",
        ])

    # ================= WRITE CSV =================
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ScanTimeUTC",
            "Role",
            "Protocol",
            "Process",
            "PID",
            "ExecutablePath",
            "ScriptPath",
            "RemoteIP",
            "RemotePort",
            "CryptoDetails",
        ])
        writer.writerows(rows)

    print(f"[+] Network crypto scan completed")
    print(f"[+] Entries written: {len(rows)}")
    print(f"[+] Output file: {OUTPUT_CSV}")

# ======================================================
if __name__ == "__main__":
    main()
