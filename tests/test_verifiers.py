"""Tests for offline verification checks."""

import zipfile
from pathlib import Path

from happ_keys.extractor import Extractor
from happ_keys.verifiers import (
    decrypt_domain_registry,
    verify_certificate_digest,
    verify_key_table_shape,
    verify_upstream_doc_anchor,
)


def test_individual_verifiers_pass_on_471(apk_path: Path) -> None:
    """Verify that all verification checks pass on version 4.7.1."""
    extractor = Extractor(apk_path)
    result = extractor.extract()
    checks = result.report.checks

    # Certificate digest
    assert "certificate_digest" in checks
    assert checks["certificate_digest"].passed is True
    assert checks["certificate_digest"].details is not None
    assert checks["certificate_digest"].details["decrypted_cert_digest"] == "g+Uz1USttQp3T0c146yMV1OLJDI="

    # Key table shape
    assert "key_table_shape" in checks
    assert checks["key_table_shape"].passed is True
    assert checks["key_table_shape"].details is not None
    assert checks["key_table_shape"].details["key_count"] == 90
    assert checks["key_table_shape"].details["all_16_bytes"] is True

    # Domain registry asset
    assert "domain_registry_asset" in checks
    assert checks["domain_registry_asset"].passed is True
    assert checks["domain_registry_asset"].details is not None
    assert checks["domain_registry_asset"].details["group_count"] == 390
    assert checks["domain_registry_asset"].details["key_used"] == "CHku5|fRC77gcp0,"
    assert checks["domain_registry_asset"].details["iv_used"] == "vrbculqfahmw"

    # Stego magic
    assert "steganography_payloads" in checks
    assert checks["steganography_payloads"].passed is True
    assert checks["steganography_payloads"].details is not None
    assert checks["steganography_payloads"].details["decoded_count"] == 90

    # Upstream doc anchor
    assert "upstream_doc_anchor" in checks
    assert checks["upstream_doc_anchor"].passed is True
    assert checks["upstream_doc_anchor"].details is not None
    assert checks["upstream_doc_anchor"].details["actual"] == 'key02:+]%4ij#P"/'


def test_verification_check_failures_detected() -> None:
    """Verify that verifiers correctly report negative results on tampered inputs."""
    blob = "uWM0lcVs0849kTwk?AqHnQy35aOM/ZtgUip+BrTHHLnSYBNwQAX0y2g==?os8iL1DE8Dee/5roJ+ZzsQ=="
    res = verify_certificate_digest(blob, "WRONG_DIGEST_HASH=", iv=b"kkkkkkkkkkkk")
    assert res.passed is False
    assert res.error is not None
    assert "mismatch" in res.error.lower()

    bad_keys = {"key01": "short", "key02": "key02:valid16by"}
    res = verify_key_table_shape(bad_keys)
    assert res.passed is False
    assert res.error is not None

    rotated_keys = {"key02": "key02:rotated1234"}
    res = verify_upstream_doc_anchor(rotated_keys)
    assert res.passed is False
    assert res.is_warning is True


def test_domain_registry_matches_reference_dump(apk_path: Path) -> None:
    """The decrypted 4.7.1 assets/data.result equals the dump kept in tests/data."""
    with zipfile.ZipFile(apk_path) as zf:
        raw = zf.read("assets/data.result")
    plain = decrypt_domain_registry(raw, key="CHku5|fRC77gcp0,", iv="vrbculqfahmw")
    assert plain == (Path(__file__).parent / "data" / "data.result.dec").read_bytes()
