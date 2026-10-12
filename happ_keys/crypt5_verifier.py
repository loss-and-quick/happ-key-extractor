"""Offline verification of captured happ://crypt5/ fixtures using pinned RSA keys."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PREFIX: str = "happ://crypt5/"


def _b64_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _swap_adjacent(data: bytes) -> bytes:
    r = bytearray(data)
    for i in range(0, len(r) - 1, 2):
        r[i], r[i + 1] = r[i + 1], r[i]
    return bytes(r)


def _swap_block_halves(data: bytes) -> bytes:
    r = bytearray(data)
    for i in range(0, len(r) - len(r) % 4, 4):
        r[i : i + 4] = r[i + 2 : i + 4] + r[i : i + 2]
    return bytes(r)


def decrypt_crypt5_link(link: str, keys_dict: dict[str, str]) -> str:
    """Decrypt a happ://crypt5/ URL link with the provided RSA keys dictionary."""
    if not link.startswith(PREFIX):
        raise ValueError(f"Link must start with {PREFIX}")

    payload = link[len(PREFIX) :].strip()
    swapped = _swap_block_halves(payload.encode("ascii"))
    marker = (swapped[:4] + swapped[-4:]).decode("ascii")
    body = swapped[4:-4]

    key_b64 = keys_dict.get(marker)
    if not key_b64:
        raise ValueError(f"Unknown crypt5 marker: {marker}")

    # Check salted mode
    salted = len(body) > 22 and not (48 <= body[12] <= 57)
    nonce = body[:12]
    salt = body[14:22] if salted else None

    pos = 22 if salted else 12
    start = pos
    while pos < len(body) and 48 <= body[pos] <= 57:
        pos += 1

    if pos == start:
        raise ValueError("Could not parse seg_len from crypt5 payload")

    seg_len = int(body[start:pos])
    packed = body[pos:]

    enc_url_str = packed[1 : 1 + seg_len].decode("ascii")
    enc_skey_str = packed[1 + seg_len :].decode("ascii")

    enc_skey_bytes = _b64_decode(enc_skey_str)
    priv_key = serialization.load_der_private_key(_b64_decode(key_b64), password=None)
    rsa_plain_bytes = priv_key.decrypt(enc_skey_bytes, padding.PKCS1v15())  # type: ignore[attr-defined]

    # Session key derivation
    swapped_skey = _swap_adjacent(rsa_plain_bytes)
    session_key = _b64_decode(swapped_skey.decode("ascii"))
    if len(session_key) != 32:
        raise ValueError(f"Expected 32-byte session key, got {len(session_key)}")

    # Salted links XOR the session key with the 8-byte salt carried in the payload.
    chacha_key = bytes(k ^ salt[i % len(salt)] for i, k in enumerate(session_key)) if salted and salt else session_key

    # ChaCha20-Poly1305 decrypt
    cipher = ChaCha20Poly1305(chacha_key)
    ct_bytes = _b64_decode(enc_url_str)
    inner_b64_bytes = cipher.decrypt(nonce, ct_bytes, None)

    # Decode final URL: swap_adjacent must be applied to the base64 intermediate bytes first!
    swapped_intermediate = _swap_adjacent(inner_b64_bytes)
    url_bytes = _b64_decode(swapped_intermediate.decode("ascii"))
    return url_bytes.decode("utf-8")


def verify_fixtures(fixtures_dir: Path, keys_file: Path) -> dict[str, Any]:
    """Verify all resp-*.json fixtures against expected values."""
    with open(keys_file) as f:
        keys_dict = json.load(f)

    results: dict[str, Any] = {}
    for p in sorted(fixtures_dir.glob("resp-*.json")):
        with open(p) as f:
            data = json.load(f)
        link = data["encrypted_link"]
        decrypted = decrypt_crypt5_link(link, keys_dict)
        results[p.name] = {
            "link": link[:30] + "...",
            "decrypted": decrypted,
            "success": decrypted.startswith("https://example.com/"),
        }
    return results
