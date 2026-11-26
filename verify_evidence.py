#!/usr/bin/env python3
"""Verify an evidence package exported from the Trustaira SOC platform.

  python verify_evidence.py evidence.zip [--trusted-public-key <hex>]

Needs only:  pip install cryptography
Without --trusted-public-key this proves the files were not changed after signing.
With it, it also proves the package was signed by the platform that owns that key.
"""
import hashlib, io, json, sys, zipfile
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    trusted = sys.argv[sys.argv.index("--trusted-public-key") + 1].lower() if "--trusted-public-key" in sys.argv else None
    z = zipfile.ZipFile(sys.argv[1])
    manifest, sig = json.loads(z.read("manifest.json")), json.loads(z.read("signature.json"))
    canon = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    problems = []
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["public_key"])).verify(bytes.fromhex(sig["signature"]), canon)
    except (InvalidSignature, ValueError, KeyError):
        problems.append("manifest signature is INVALID")
    for name, digest in manifest["files"].items():
        try:
            if hashlib.sha256(z.read(name)).hexdigest() != digest:
                problems.append(f"{name}: content changed after signing")
        except KeyError:
            problems.append(f"{name}: missing")
    if trusted and trusted != sig["public_key"].lower():
        problems.append("signed by a different key than the trusted one")
    print("Incident :", manifest.get("incident_id"), "| generated", manifest.get("generated_at"), "by", manifest.get("generated_by"))
    print("Signer   :", sig["public_key"])
    if problems:
        print("RESULT   : FAILED"); [print("  -", p) for p in problems]; sys.exit(1)
    print("RESULT   : OK - all", len(manifest["files"]), "files match the signed manifest")

if __name__ == "__main__":
    main()
