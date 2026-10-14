"""Extraction and offline verification of the INCY `incy://crypt1/` key material.

Unlike Happ, INCY keeps the key for its URL-obfuscation scheme in plain sight: two 4 KiB
assets in ``res/raw``. The key is one SHA-256 over a fixed salt and a 32-byte window of each
asset, with no secret input, so extraction is a zip read plus a hash and the result can be
checked against the fingerprint the vendor pins in every reference implementation.

The wire format and the derivation are specified in
``docs/11-incy-url-obfuscation.md`` of the happ-sub documentation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX: str = "incy://crypt1/"
KEYMAT_ASSETS: tuple[str, str] = ("res/raw/incy_assets_a.bin", "res/raw/incy_assets_b.bin")
KEYMAT_A_OFFSET: int = 1024
KEYMAT_B_OFFSET: int = 2048
KEYMAT_LEN: int = 32
SALT_PARTS: tuple[str, ...] = ("incy", "deep", "crypt1", "v2026.06")
IV_LEN: int = 12
TAG_LEN: int = 16
MIN_WIRE_LEN: int = IV_LEN + TAG_LEN + 1

#: SHA-256 of the derived key, asserted by the vendor's JS, Python, PHP and Go ports.
EXPECTED_FINGERPRINT: str = "b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c"
#: SHA-256 of the two assets, as shipped in INCY 3.7.0.
KEYMAT_A_SHA256: str = "29047e8cbf382932a491608ae9202e3efe447f2739f81dca25b37019dc24d8f7"
KEYMAT_B_SHA256: str = "0cc7e650c25b10bd53587f01424bc901810ba6ea43af4dac49a3e7d9c5ac10ec"


class IncyKeymatError(Exception):
    """The APK does not carry usable keymat assets, or they derive an unexpected key."""


@dataclass(frozen=True)
class IncyKeymat:
    """The two keymat blobs read out of an INCY APK, with their provenance digests."""

    a: bytes
    b: bytes
    source: str

    @property
    def a_sha256(self) -> str:
        """SHA-256 of the first asset."""
        return hashlib.sha256(self.a).hexdigest()

    @property
    def b_sha256(self) -> str:
        """SHA-256 of the second asset."""
        return hashlib.sha256(self.b).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Return the keymat as JSON-friendly data, without the raw bytes."""
        return {
            "source": self.source,
            "keymat_a_len": len(self.a),
            "keymat_b_len": len(self.b),
            "keymat_a_sha256": self.a_sha256,
            "keymat_b_sha256": self.b_sha256,
        }


@dataclass(frozen=True)
class IncyLink:
    """A decrypted `incy://crypt1/` link."""

    url: str
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the link as the JSON payload the client reads."""
        payload: dict[str, Any] = {"url": self.url, "v": 1}
        if self.name:
            payload["n"] = self.name
        return payload


def read_keymat(apk_path: Path | str) -> IncyKeymat:
    """Read both keymat assets from an INCY APK."""
    apk_path = Path(apk_path)
    blobs: list[bytes] = []
    with zipfile.ZipFile(apk_path) as zf:
        for entry in KEYMAT_ASSETS:
            try:
                blobs.append(zf.read(entry))
            except KeyError as exc:
                raise IncyKeymatError(f"missing asset: {entry}") from exc
    return IncyKeymat(a=blobs[0], b=blobs[1], source=str(apk_path))


def derive_key(keymat: IncyKeymat, *, verify: bool = True) -> bytes:
    """Derive K1 from a keymat, asserting the vendor fingerprint by default."""
    a_window = keymat.a[KEYMAT_A_OFFSET : KEYMAT_A_OFFSET + KEYMAT_LEN]
    b_window = keymat.b[KEYMAT_B_OFFSET : KEYMAT_B_OFFSET + KEYMAT_LEN]
    if len(a_window) != KEYMAT_LEN:
        raise IncyKeymatError(f"keymat_a is {len(keymat.a)} bytes, needs {KEYMAT_LEN} at offset {KEYMAT_A_OFFSET}")
    if len(b_window) != KEYMAT_LEN:
        raise IncyKeymatError(f"keymat_b is {len(keymat.b)} bytes, needs {KEYMAT_LEN} at offset {KEYMAT_B_OFFSET}")

    seed = "".join(SALT_PARTS).encode() + a_window + b_window
    key = hashlib.sha256(seed).digest()
    if verify:
        fingerprint = hashlib.sha256(key).hexdigest()
        if fingerprint != EXPECTED_FINGERPRINT:
            raise IncyKeymatError(f"keymat does not derive the documented K1 (fingerprint {fingerprint})")
    return key


def fingerprint(key: bytes) -> str:
    """Return the SHA-256 of `key`, the value to compare against `EXPECTED_FINGERPRINT`."""
    return hashlib.sha256(key).hexdigest()


def _decode_payload(payload: str) -> bytes:
    """Decode a payload the way the client does: URL-safe unpadded first, standard as fallback."""
    stripped = "".join(payload.split())
    padded = stripped + "=" * (-len(stripped) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(padded)
        except (binascii.Error, ValueError):
            continue
    raise ValueError("payload is not base64")


def decrypt_payload(payload: str, key: bytes) -> IncyLink:
    """Decrypt the payload of an `incy://crypt1/` link, without the scheme prefix."""
    wire = _decode_payload(payload)
    if len(wire) < MIN_WIRE_LEN:
        raise ValueError(f"decoded payload is {len(wire)} bytes, minimum is {MIN_WIRE_LEN}")
    try:
        plaintext = AESGCM(key).decrypt(wire[:IV_LEN], wire[IV_LEN:], None)
    except InvalidTag as exc:
        raise ValueError("AES-256-GCM authentication failed") from exc

    try:
        parsed = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"plaintext is not JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("plaintext is not a JSON object")

    url = parsed.get("url")
    if not isinstance(url, str) or not url:
        raise ValueError("plaintext has no non-empty url field")
    name = parsed.get("n")
    return IncyLink(url=url, name=name if isinstance(name, str) and name else None)


def decrypt_link(link: str, key: bytes) -> IncyLink:
    """Decrypt a full `incy://crypt1/<payload>` link."""
    link = link.strip()
    if link[: len(PREFIX)].lower() != PREFIX:
        raise ValueError(f"link must start with {PREFIX}")
    return decrypt_payload(link[len(PREFIX) :].strip("/"), key)


def encrypt_link(url: str, key: bytes, name: str | None = None, iv: bytes | None = None) -> str:
    """Build an `incy://crypt1/` link.

    The IV is a parameter so that fixture builders are deterministic; omit it in production,
    where a fresh value must be drawn per link the way the client does.
    """
    payload: dict[str, Any] = {"url": url, "v": 1}
    if name:
        payload["n"] = name
    plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    iv = iv if iv is not None else secrets.token_bytes(IV_LEN)
    if len(iv) != IV_LEN:
        raise ValueError(f"iv must be {IV_LEN} bytes")
    sealed = AESGCM(key).encrypt(iv, plaintext, None)
    return PREFIX + base64.urlsafe_b64encode(iv + sealed).decode().rstrip("=")


def verify_fixtures(fixtures_dir: Path | str, key: bytes | None = None) -> dict[str, Any]:
    """Decrypt every `incy://crypt1/` sample in a fixtures directory."""
    if key is None:
        keymat = read_keymat_from_fixtures(Path(fixtures_dir))
        key = derive_key(keymat)

    samples_path = Path(fixtures_dir) / "incy-crypt1-samples.json"
    samples = json.loads(samples_path.read_text(encoding="utf-8"))

    results: dict[str, Any] = {}
    for index, sample in enumerate(samples["samples"], start=1):
        # Notes repeat across generated samples, so the index keeps every result addressable.
        note = f"{index:02d} {sample.get('note', 'sample')}"
        link = sample["link"]
        expected = sample["plaintext"]
        try:
            decrypted = decrypt_link(link, key)
            # ensure_ascii=False: the vendor's encoders write the name as UTF-8, not as \u escapes.
            actual = json.dumps(decrypted.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            results[note] = {
                "link": link[:38] + "...",
                "url": decrypted.url,
                "name": decrypted.name,
                "success": actual == expected,
            }
        except Exception as exc:
            results[note] = {"link": link[:38] + "...", "error": str(exc), "success": False}
    return results


def read_keymat_from_fixtures(fixtures_dir: Path) -> IncyKeymat:
    """Rebuild a keymat from the Base64 blobs a fixtures directory ships.

    `happ-sub` embeds the same two assets as `src/keys/incy-keymat.json`, which lets the
    fixtures verify without an APK.
    """
    path = fixtures_dir / "incy-keymat.json"
    if not path.is_file():
        raise IncyKeymatError(f"missing keymat: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    return IncyKeymat(
        a=base64.b64decode(data["keymat_a_b64"]),
        b=base64.b64decode(data["keymat_b_b64"]),
        source=str(path),
    )


def keymat_json(keymat: IncyKeymat) -> str:
    """Render a keymat as the `{"keymat_a_b64": …, "keymat_b_b64": …}` JSON the crate embeds."""
    return json.dumps(
        {
            "source": keymat.source,
            "keymat_a_b64": base64.b64encode(keymat.a).decode(),
            "keymat_b_b64": base64.b64encode(keymat.b).decode(),
        },
        indent=2,
    )
