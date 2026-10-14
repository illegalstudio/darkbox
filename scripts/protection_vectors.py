#!/usr/bin/env python3
"""Generate independent protection 1.0.0 vectors with cryptography/OpenSSL.

Run: uv run --with cryptography python scripts/protection_vectors.py --check
Only unpublished bundles may be rewritten. All keys below are public test keys.
"""
import argparse
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = "studio.illegal.darkbox.protection"
VERSION = "1.0.0"
PACKAGE = "00112233445566778899aabbccddeeff"


def lp(text):
    value = text.encode("utf-8")
    return struct.pack(">I", len(value)) + value


def vectors():
    key = bytes(range(32))
    definitions = [
        ("file", {"kind": "file", "path": "assets/private.bin"}, b"Private attachment\x00\xff"),
        ("empty-file", {"kind": "file", "path": "assets/empty.bin"}, b""),
        ("sqlite", {"kind": "sqlite", "database": "data/project.sqlite", "table": "notes", "column": "secret", "record_id": "r-\u00e9-1"}, b'{"text":"private","count":3}'),
    ]
    result = []
    for index, (name, location, plaintext) in enumerate(definitions):
        nonce = bytes.fromhex("0102030405060708") + struct.pack(">I", index + 1)
        header = b"DBXP\x01\x01\x00\x00" + nonce + struct.pack(">Q", len(plaintext))
        aad = b"Darkbox-PROTECTION-AAD\x00" + header + b"".join(lp(s) for s in (NAMESPACE, VERSION, PACKAGE, "test-key"))
        if location["kind"] == "file":
            aad += b"\x01" + lp(location["path"])
        else:
            aad += b"\x02" + b"".join(lp(location[s]) for s in ("database", "table", "column", "record_id"))
        encrypted = AESGCM(key).encrypt(nonce, plaintext, aad)
        result.append({"name": name, "context": {"package_id": PACKAGE, "key_id": "test-key", "location": location}, "keyHex": key.hex(), "nonceHex": nonce.hex(), "plaintextHex": plaintext.hex(), "aadHex": aad.hex(), "ciphertextHex": encrypted[:-16].hex(), "tagHex": encrypted[-16:].hex(), "blockHex": (header + encrypted).hex()})
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    signer = Ed25519PrivateKey.from_private_bytes(seed)
    # Exact bytes are deliberately distinct from any pretty-printed JSON form.
    manifest = b'{"extensions":{"studio.illegal.darkbox.protection":{"version":"1.0.0","required":true,"data":{"packageId":"00112233445566778899aabbccddeeff","signature":{"algorithm":"Ed25519","signerId":"test-signer","path":"extensions/studio.illegal.darkbox.protection/manifest.ed25519"},"inventory":[],"files":[],"sqlite":[]}}}}\n'
    return {"extension": NAMESPACE, "version": VERSION, "generator": "Python cryptography, OpenSSL backend", "blocks": result, "signature": {"seedHex": seed.hex(), "publicKeyHex": signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(), "manifestHex": manifest.hex(), "signatureHex": signer.sign(manifest).hex()}, "rfc8032EmptyMessageSignatureHex": signer.sign(b"").hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--write", action="store_true")
    args = parser.parse_args()
    path = ROOT / "archive/1.1.0/docs/darkbox/protection/1.0.0.vectors.json"
    expected = (json.dumps(vectors(), indent=2, ensure_ascii=True) + "\n").encode()
    if args.check:
        if path.read_bytes() != expected:
            raise SystemExit("Protection vectors differ")
    else:
        registry = json.loads((ROOT / "versions.json").read_bytes())["versions"]
        if next(row for row in registry if row["version"] == "1.1.0")["released"]:
            raise SystemExit("Published bundles cannot be rewritten")
        path.write_bytes(expected)
    print("Protection 1.0.0 vectors match cryptography/OpenSSL")


if __name__ == "__main__":
    main()
