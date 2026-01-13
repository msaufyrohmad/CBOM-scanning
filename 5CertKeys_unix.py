#!/usr/bin/env python3

import os
import csv
import hashlib
from datetime import timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

OUTPUT_CSV = "crypto_cert_key_inventory_detailed.csv"

SCAN_EXTENSIONS = {
    ".crt", ".cer", ".pem", ".der",
    ".key", ".pk8",
    ".p12", ".pfx"
}

def is_candidate(filename):
    return any(filename.lower().endswith(ext) for ext in SCAN_EXTENSIONS)

def short_fingerprint(data):
    return hashlib.sha256(data).hexdigest()[:32]

def scan_certificate(path, data):
    cert = x509.load_pem_x509_certificate(data, default_backend())
    pubkey = cert.public_key()

    algo = pubkey.__class__.__name__
    key_size = getattr(pubkey, "key_size", "unknown")

    modulus_fp = ""
    exponent = ""
    curve = ""

    if isinstance(pubkey, rsa.RSAPublicKey):
        modulus_fp = hashlib.sha256(
            pubkey.public_numbers().n.to_bytes(
                (pubkey.key_size + 7) // 8, "big"
            )
        ).hexdigest()[:32]
        exponent = pubkey.public_numbers().e

    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        curve = pubkey.curve.name

    sig_algo = cert.signature_algorithm_oid._name or "unknown"
    sig_hash = (
        cert.signature_hash_algorithm.name
        if cert.signature_hash_algorithm
        else "unknown"
    )

    return {
        "type": "certificate",
        "algorithm": algo,
        "key_size": key_size,
        "curve": curve,
        "rsa_modulus_fp": modulus_fp,
        "rsa_exponent": exponent,
        "signature_algorithm": sig_algo,
        "signature_hash": sig_hash,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": hex(cert.serial_number),
        "not_before": cert.not_valid_before.astimezone(timezone.utc).isoformat(),
        "not_after": cert.not_valid_after.astimezone(timezone.utc).isoformat(),
        "fingerprint_sha1": cert.fingerprint(hashes.SHA1()).hex(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }

def scan_private_key(path, data):
    key = serialization.load_pem_private_key(
        data, password=None, backend=default_backend()
    )

    algo = key.__class__.__name__
    key_size = getattr(key, "key_size", "unknown")

    modulus_fp = ""
    exponent = ""
    curve = ""

    if isinstance(key, rsa.RSAPrivateKey):
        modulus_fp = hashlib.sha256(
            key.private_numbers().public_numbers.n.to_bytes(
                (key.key_size + 7) // 8, "big"
            )
        ).hexdigest()[:32]
        exponent = key.private_numbers().public_numbers.e

    elif isinstance(key, ec.EllipticCurvePrivateKey):
        curve = key.curve.name

    return {
        "type": "private_key",
        "algorithm": algo,
        "key_size": key_size,
        "curve": curve,
        "rsa_modulus_fp": modulus_fp,
        "rsa_exponent": exponent,
        "signature_algorithm": "",
        "signature_hash": "",
        "subject": "",
        "issuer": "",
        "serial": "",
        "not_before": "",
        "not_after": "",
        "fingerprint_sha1": short_fingerprint(data),
        "fingerprint_sha256": hashlib.sha256(data).hexdigest(),
    }

def analyze_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()

        if b"BEGIN CERTIFICATE" in data:
            return scan_certificate(path, data)

        if b"BEGIN PRIVATE KEY" in data or b"BEGIN RSA PRIVATE KEY" in data:
            return scan_private_key(path, data)

    except Exception:
        pass

    return None

def main(root="/"):
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "path",
            "file_type",
            "algorithm",
            "key_size",
            "curve",
            "rsa_modulus_fingerprint",
            "rsa_exponent",
            "signature_algorithm",
            "signature_hash",
            "subject",
            "issuer",
            "serial",
            "not_before",
            "not_after",
            "fingerprint_sha1",
            "fingerprint_sha256",
        ])

        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                if not is_candidate(name):
                    continue

                path = os.path.join(dirpath, name)
                result = analyze_file(path)

                if result:
                    writer.writerow([
                        path,
                        result["type"],
                        result["algorithm"],
                        result["key_size"],
                        result["curve"],
                        result["rsa_modulus_fp"],
                        result["rsa_exponent"],
                        result["signature_algorithm"],
                        result["signature_hash"],
                        result["subject"],
                        result["issuer"],
                        result["serial"],
                        result["not_before"],
                        result["not_after"],
                        result["fingerprint_sha1"],
                        result["fingerprint_sha256"],
                    ])

    print(f"[+] Scan complete → {OUTPUT_CSV}")

if __name__ == "__main__":
    main("/")

