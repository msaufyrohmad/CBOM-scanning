#!/usr/bin/env python3
"""
PTPKM
scanner_bit.py (cross-platform)
Linux / Windows supported
JSON + CSV output
"""

import subprocess, xmltodict, json, sys, pathlib, argparse, re, platform, shutil, csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------------- OS & TOOL DETECTION ----------------

def detect_os():
    return platform.system().lower()  # windows | linux | darwin

def find_sslscan_binary():
    """
    Locate sslscan or sslscan.exe
    """
    candidates = ["sslscan", "sslscan.exe"]
    for c in candidates:
        path = shutil.which(c)
        if path:
            return path
    return None

OS_TYPE = detect_os()
SSLSCAN_BIN = find_sslscan_binary()

# ---------------- REGEX ----------------

PEM_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----(?:\r?\n|[\s\S]*?)-----END CERTIFICATE-----",
    flags=re.MULTILINE,
)

CLIENT_CA_RE = re.compile(
    r"<client[-_]?ca(?:s)?(?:[^>]*)>([\s\S]*?)</client[-_]?ca(?:s)?>",
    flags=re.IGNORECASE,
)

# ---------------- SSLScan Runner ----------------

def run_sslscan_xml(target: str, timeout: int = 90):
    if not SSLSCAN_BIN:
        return target, None, None, "sslscan not found (install or use WSL on Windows)"

    cmd = [
        SSLSCAN_BIN,
        "--xml=-",
        "--show-certificates",
        "--show-cipher-ids",
        target,
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return target, proc.stdout, proc.returncode, proc.stderr
    except subprocess.TimeoutExpired:
        return target, None, None, f"timeout after {timeout}s"

# ---------------- XML HELPERS ----------------

def parse_sslscan_xml(xml_text):
    if not xml_text:
        return None
    try:
        return xmltodict.parse(xml_text)
    except Exception as e:
        return {"_parse_error": str(e)}

def normalize_target_filename(target: str):
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", target)

def find_pem_blocks_in_text(text):
    return PEM_BLOCK_RE.findall(text or "")

# ---------------- EXTRACTION ----------------

def extract_ciphers(parsed_xml):
    ciphers = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k.lower().startswith("cipher"):
                    if isinstance(v, list):
                        for i in v:
                            ciphers.append(i)
                    else:
                        ciphers.append(v)
                else:
                    walk(v)
        elif isinstance(node, list):
            for i in node:
                walk(i)

    if parsed_xml:
        walk(parsed_xml)

    out = []
    for c in ciphers:
        if isinstance(c, dict):
            out.append({
                "sslversion": c.get("@sslversion"),
                "status": c.get("@status"),
                "strength": c.get("@strength") or c.get("@bits"),
                "cipher": c.get("cipherName") or c.get("name") or c.get("#text"),
            })
    return out

def extract_client_cas(parsed_xml, raw_xml):
    cas = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if "client" in k.lower() and "ca" in k.lower():
                    cas.append(str(v))
                else:
                    walk(v)
        elif isinstance(node, list):
            for i in node:
                walk(i)

    if parsed_xml:
        walk(parsed_xml)

    if not cas:
        cas.extend(CLIENT_CA_RE.findall(raw_xml or ""))

    return list(set(cas))

def extract_certificates(parsed, raw):
    pems = find_pem_blocks_in_text(raw)
    return list(dict.fromkeys(pems))

# ---------------- CSV WRITER ----------------

def write_combined_csv(results, outdir):
    csv_path = outdir / "combined_results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "scan_time",
            "target",
            "os",
            "scanner",
            "tls_version",
            "cipher",
            "cipher_strength",
            "cipher_status",
            "client_cas_count",
            "cert_chain_length",
            "errors",
        ])

        for target, r in results.items():
            if not r.get("ciphers"):
                writer.writerow([
                    r["scanned_at"],
                    target,
                    r["os"],
                    r["scanner"],
                    "",
                    "",
                    "",
                    "",
                    len(r.get("client_cas", [])),
                    len(r.get("certificates", [])),
                    r.get("error"),
                ])
            else:
                for c in r["ciphers"]:
                    writer.writerow([
                        r["scanned_at"],
                        target,
                        r["os"],
                        r["scanner"],
                        c.get("sslversion"),
                        c.get("cipher"),
                        c.get("strength"),
                        c.get("status"),
                        len(r.get("client_cas", [])),
                        len(r.get("certificates", [])),
                        r.get("error"),
                    ])

# ---------------- MAIN ----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("targets_file")
    ap.add_argument("--out-dir", default="sslscan_results")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=90)
    args = ap.parse_args()

    outdir = pathlib.Path(args.out_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    targets = [t.strip() for t in open(args.targets_file) if t.strip()]

    results = {}

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(run_sslscan_xml, t, args.timeout): t for t in targets}

        for fut in as_completed(futures):
            target, xml_out, rc, stderr = fut.result()
            short = normalize_target_filename(target)

            entry = {
                "target": target,
                "scanned_at": datetime.utcnow().isoformat(),
                "os": OS_TYPE,
                "scanner": SSLSCAN_BIN or "none",
                "returncode": rc,
                "error": stderr,
                "ciphers": [],
                "client_cas": [],
                "certificates": [],
            }

            if xml_out:
                parsed = parse_sslscan_xml(xml_out)
                entry["ciphers"] = extract_ciphers(parsed)
                entry["client_cas"] = extract_client_cas(parsed, xml_out)
                entry["certificates"] = extract_certificates(parsed, xml_out)

            (outdir / f"{short}.json").write_text(
                json.dumps(entry, indent=2), encoding="utf-8"
            )

            results[target] = entry
            print(f"[+] {target} scanned")

    (outdir / "combined_results.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )

    write_combined_csv(results, outdir)

    print(f"[✓] Scan complete ({OS_TYPE}) → {outdir}")

# ---------------- ENTRY ----------------

if __name__ == "__main__":
    main()
