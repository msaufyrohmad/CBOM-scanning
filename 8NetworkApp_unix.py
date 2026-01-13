#!/usr/bin/env python3

import psutil
import socket
import ssl
import os
import csv
from datetime import datetime

OUTPUT_CSV = "tls_crypto_inventory.csv"

INTERPRETERS = ("python", "php", "node", "perl", "ruby", "bash", "sh")

# -------------------------------
# Protocol detection
# -------------------------------
def detect_protocol(port):
    return {
        80: "HTTP",
        443: "HTTPS",
        53: "DNS",
        22: "SSH",
        25: "SMTP",
        587: "SMTP-STARTTLS",
        21: "FTP",
        3306: "MySQL",
        5432: "PostgreSQL",
    }.get(port, "UNKNOWN")

# -------------------------------
# Identify application
# -------------------------------
def identify_application(proc):
    try:
        exe = proc.exe()
        cmd = proc.cmdline()
    except Exception:
        return "", "", ""

    app = exe
    script = ""

    if any(proc.name().startswith(i) for i in INTERPRETERS):
        for arg in cmd[1:]:
            if os.path.isfile(arg):
                app = arg
                script = arg
                break

    return proc.name(), exe, script

# -------------------------------
# Parse cipher suite
# -------------------------------
def parse_cipher(cipher):
    if not cipher:
        return "", "", "", ""

    name, proto, bits = cipher
    parts = name.split("_")

    encryption = parts[1] if len(parts) > 1 else ""
    hash_alg = parts[-1] if "SHA" in parts[-1] else ""
    primitive = "AEAD" if ("GCM" in name or "POLY1305" in name) else "Encryption"

    return name, encryption, primitive, bits

# -------------------------------
# TLS probing (client OR server)
# -------------------------------
def probe_tls(host, port):
    result = {
        "tls_version": "",
        "cipher": "",
        "encryption": "",
        "primitive": "",
        "hash": "",
        "key_size": "",
    }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["tls_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    name, enc, prim, bits = parse_cipher(cipher)
                    result["cipher"] = name
                    result["encryption"] = enc
                    result["primitive"] = prim
                    result["key_size"] = bits
                    if "SHA" in name:
                        result["hash"] = name.split("_")[-1]
    except Exception:
        pass

    return result

# -------------------------------
# MAIN
# -------------------------------
def main():
    rows = []
    seen = set()
    timestamp = datetime.utcnow().isoformat()

    # -------- TLS CLIENT SCAN --------
    for conn in psutil.net_connections(kind="inet"):
        if not conn.pid or not conn.raddr:
            continue

        proto = detect_protocol(conn.raddr.port)
        if proto != "HTTPS":
            continue

        key = (conn.pid, conn.raddr.ip, conn.raddr.port)
        if key in seen:
            continue
        seen.add(key)

        try:
            proc = psutil.Process(conn.pid)
            pname, exe, script = identify_application(proc)
            crypto = probe_tls(conn.raddr.ip, conn.raddr.port)

            rows.append([
                timestamp,
                "CLIENT",
                pname,
                conn.pid,
                exe,
                script,
                proto,
                conn.raddr.ip,
                conn.raddr.port,
                crypto["tls_version"],
                crypto["cipher"],
                crypto["encryption"],
                crypto["primitive"],
                crypto["hash"],
                crypto["key_size"],
            ])
        except Exception:
            continue

    # -------- TLS SERVER SCAN (LOCAL) --------
    local_hosts = set()
    for conn in psutil.net_connections(kind="inet"):
        if conn.laddr and conn.laddr.port == 443:
            local_hosts.add(conn.laddr.ip)

    for host in local_hosts:
        crypto = probe_tls(host, 443)
        rows.append([
            timestamp,
            "SERVER",
            "LOCAL_TLS_SERVER",
            "",
            "",
            "",
            "HTTPS",
            host,
            443,
            crypto["tls_version"],
            crypto["cipher"],
            crypto["encryption"],
            crypto["primitive"],
            crypto["hash"],
            crypto["key_size"],
        ])

    # -------- WRITE CSV --------
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ScanTimeUTC",
            "Role",
            "Process",
            "PID",
            "Executable",
            "Script",
            "Protocol",
            "RemoteIP",
            "RemotePort",
            "TLSVersion",
            "CipherSuite",
            "EncryptionAlgo",
            "Primitive",
            "Hash/MAC",
            "KeySize",
        ])
        writer.writerows(rows)

    print(f"[+] TLS scan completed")
    print(f"[+] Entries written: {len(rows)}")
    print(f"[+] Output file: {OUTPUT_CSV}")

# -------------------------------
if __name__ == "__main__":
    main()

