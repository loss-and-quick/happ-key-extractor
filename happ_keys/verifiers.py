"""Domain-specific verifiers proving extracted key material and APK assets."""

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import zstandard
from Crypto.Cipher import AES


@dataclass
class CheckResult:
    """Outcome of a single verification step."""

    name: str
    description: str
    passed: bool
    is_warning: bool = False
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "passed": self.passed,
            "is_warning": self.is_warning,
            "details": self.details,
            "error": self.error,
        }


@dataclass
class VerificationReport:
    """Aggregated verification results."""

    checks: dict[str, CheckResult]
    all_passed: bool
    warnings_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "all_passed": self.all_passed,
            "warnings_count": self.warnings_count,
            "checks": {k: v.to_dict() for k, v in self.checks.items()},
        }


def verify_certificate_digest(
    anti_tamper_blob: str,
    apk_cert_sha1_b64: str,
    iv: bytes = b"kkkkkkkkkkkk",
) -> CheckResult:
    """Decrypt the anti-tamper signature blob and verify it matches the APK's certificate digest."""
    parts = anti_tamper_blob.split("?")
    if len(parts) != 3:
        return CheckResult(
            name="certificate_digest",
            description="Anti-tamper signing certificate digest match",
            passed=False,
            error=f"Malformed anti-tamper blob, expected 3 parts, got {len(parts)}",
        )

    key_literal, ct_b64, tag_b64 = parts
    try:
        ct = base64.b64decode(ct_b64)
        tag = base64.b64decode(tag_b64)
        cipher = AES.new(key_literal.encode("utf-8"), AES.MODE_GCM, nonce=iv, mac_len=16)
        decrypted_digest_bytes = cipher.decrypt_and_verify(ct, tag)
        decrypted_digest = decrypted_digest_bytes.decode("utf-8")

        passed = decrypted_digest == apk_cert_sha1_b64
        return CheckResult(
            name="certificate_digest",
            description="Anti-tamper signing certificate digest match",
            passed=passed,
            details={
                "decrypted_cert_digest": decrypted_digest,
                "actual_apk_cert_digest": apk_cert_sha1_b64,
            },
            error=None
            if passed
            else f"Certificate digest mismatch: decrypted {decrypted_digest!r} != actual {apk_cert_sha1_b64!r}",
        )
    except Exception as e:
        return CheckResult(
            name="certificate_digest",
            description="Anti-tamper signing certificate digest match",
            passed=False,
            error=f"Anti-tamper decryption failed: {e}",
        )


def verify_key_table_shape(keys: Mapping[str, str]) -> CheckResult:
    """Verify key table integrity: exactly 90 entries, 16 bytes each, key01..key90 sequence."""
    count = len(keys)
    expected_keyids = [f"key{i:02d}" for i in range(1, 91)]
    actual_keyids = sorted(keys.keys())

    errors: list[str] = []
    if count != 90:
        errors.append(f"Expected 90 entries, got {count}")

    if actual_keyids != expected_keyids:
        errors.append(f"Key IDs differ from key01..key90 sequence (found {len(actual_keyids)} distinct)")

    for kid, val in keys.items():
        if len(val) != 16:
            errors.append(f"Key {kid} length is {len(val)}, expected 16 bytes")
        parts = val.split(":")
        if len(parts) < 2 or parts[0] != kid:
            errors.append(f"Key {kid} prefix mismatch: {val!r}")

    passed = len(errors) == 0
    return CheckResult(
        name="key_table_shape",
        description="Key table layout (90 entries, 16 bytes each, key01..key90)",
        passed=passed,
        details={
            "key_count": count,
            "all_16_bytes": all(len(v) == 16 for v in keys.values()),
            "distinct_keyids": len(set(keys.keys())),
        },
        error="; ".join(errors) if errors else None,
    )


def decrypt_domain_registry(data_result_bytes: bytes, key: str, iv: str) -> bytes:
    """Decrypt and decompress assets/data.result.

    The 16-byte GCM tag is stored as 24 base64 characters split around the ciphertext:
    `b64(tag)[:12] || ciphertext || b64(tag)[12:]`. The plaintext is a zstd frame of JSON.
    """
    if len(data_result_bytes) < 24:
        raise ValueError(f"assets/data.result too short: {len(data_result_bytes)} bytes")
    head = data_result_bytes[:12].decode("ascii")
    tail = data_result_bytes[-12:].decode("ascii")
    tag = base64.b64decode(head + tail)
    cipher = AES.new(key.encode("utf-8"), AES.MODE_GCM, nonce=iv.encode("utf-8"), mac_len=16)
    plain = cipher.decrypt_and_verify(data_result_bytes[12:-12], tag)
    return zstandard.ZstdDecompressor().decompress(plain)


def verify_domain_registry_asset(
    data_result_bytes: bytes,
    key_35: str,
    key_literal: str,
    iv_1059: str,
) -> CheckResult:
    """Verify that assets/data.result decrypts cleanly with special JNI values and decompresses to valid JSON."""
    key_str = key_35 + key_literal
    iv_str = iv_1059
    try:
        decompressed = decrypt_domain_registry(data_result_bytes, key_str, iv_str)
        parsed_groups = json.loads(decompressed)

        group_count = len(parsed_groups) if isinstance(parsed_groups, dict) else 0
        passed = group_count > 0

        return CheckResult(
            name="domain_registry_asset",
            description="Encrypted domain registry asset (assets/data.result)",
            passed=passed,
            details={
                "group_count": group_count,
                "decompressed_size": len(decompressed),
                "key_used": key_str,
                "iv_used": iv_str,
            },
            error=None if passed else f"Expected non-empty dict in data.result, got {type(parsed_groups)}",
        )
    except Exception as e:
        return CheckResult(
            name="domain_registry_asset",
            description="Encrypted domain registry asset (assets/data.result)",
            passed=False,
            error=f"data.result decryption/decompression failed: {e}",
        )


def verify_steganography_payloads(stego_strings: Mapping[int, str], expected_count: int = 90) -> CheckResult:
    """Verify that all steganographic PNG icons decoded with valid !encoded! headers."""
    actual_count = len(stego_strings)
    passed = actual_count == expected_count and all(v is not None and len(v) > 0 for v in stego_strings.values())

    return CheckResult(
        name="steganography_payloads",
        description=f"Stego icon decoding (!encoded! magic check on all {expected_count} payloads)",
        passed=passed,
        details={
            "decoded_count": actual_count,
            "expected_count": expected_count,
        },
        error=None if passed else f"Only {actual_count}/{expected_count} stego payloads decoded successfully",
    )


def verify_upstream_doc_anchor(keys: Mapping[str, str]) -> CheckResult:
    """Verify key02 against the public vendor provider documentation (key02:+]%4ij#P\"/)."""
    expected = 'key02:+]%4ij#P"/'
    actual = keys.get("key02")

    passed = actual == expected
    return CheckResult(
        name="upstream_doc_anchor",
        description='Upstream reference test key (key02 == key02:+]%4ij#P"/)',
        passed=passed,
        is_warning=not passed,
        details={
            "actual": actual,
            "expected": expected,
        },
        error=None if passed else f"key02 differs from upstream doc anchor: {actual!r} != {expected!r}",
    )
