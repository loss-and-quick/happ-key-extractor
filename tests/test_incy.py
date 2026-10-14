"""The `incy://crypt1/` key material: derivation from the APK, and offline decryption."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import zipfile
from pathlib import Path

import pytest

from happ_keys import incy
from happ_keys.incy import IncyKeymatError

DATA_DIR = Path(__file__).parent / "data" / "incy"
SAMPLES = DATA_DIR / "incy-crypt1-samples.json"

#: Set to an INCY APK path to check the real assets; the test skips otherwise, the way the
#: Happ extraction tests skip without HAPP_APK_CACHE.
INCY_APK_ENV = "INCY_APK"
PINNED_VECTOR_URL = "https://sub.example.com/test-vector"


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64url_encode(wire: bytes) -> str:
    return base64.urlsafe_b64encode(wire).decode().rstrip("=")


@pytest.fixture
def key() -> bytes:
    return incy.derive_key(incy.read_keymat_from_fixtures(DATA_DIR))


def test_bundled_keymat_matches_the_pinned_digests() -> None:
    keymat = incy.read_keymat_from_fixtures(DATA_DIR)

    assert keymat.a_sha256 == incy.KEYMAT_A_SHA256
    assert keymat.b_sha256 == incy.KEYMAT_B_SHA256
    assert len(keymat.a) == len(keymat.b) == 4096


def test_derived_key_matches_the_vendor_fingerprint() -> None:
    key = incy.derive_key(incy.read_keymat_from_fixtures(DATA_DIR))

    assert incy.fingerprint(key) == incy.EXPECTED_FINGERPRINT
    assert key.hex() == "f6d40ea0c8a8899d7c682d09ba0d4165dfe2b3dd45e6bb3e25cb233cf00c2462"


def test_derivation_is_the_documented_computation() -> None:
    keymat = incy.read_keymat_from_fixtures(DATA_DIR)
    seed = (
        b"incydeepcrypt1v2026.06"
        + keymat.a[incy.KEYMAT_A_OFFSET : incy.KEYMAT_A_OFFSET + incy.KEYMAT_LEN]
        + keymat.b[incy.KEYMAT_B_OFFSET : incy.KEYMAT_B_OFFSET + incy.KEYMAT_LEN]
    )

    assert incy.derive_key(keymat, verify=False) == hashlib.sha256(seed).digest()


def test_a_truncated_or_foreign_keymat_is_rejected() -> None:
    keymat = incy.read_keymat_from_fixtures(DATA_DIR)

    with pytest.raises(IncyKeymatError, match="keymat_a"):
        incy.derive_key(incy.IncyKeymat(a=keymat.a[:100], b=keymat.b, source="test"))

    with pytest.raises(IncyKeymatError, match="documented K1"):
        incy.derive_key(incy.IncyKeymat(a=bytes(4096), b=bytes(4096), source="test"))


def test_every_sample_decrypts_to_its_recorded_plaintext() -> None:
    results = incy.verify_fixtures(DATA_DIR)

    assert len(results) == 5
    for note, result in results.items():
        assert result["success"] is True, f"{note}: {result}"
        assert result["url"]


def test_the_pinned_vendor_vector_matches(key: bytes) -> None:
    samples = json.loads(SAMPLES.read_text(encoding="utf-8"))
    vector = samples["samples"][0]
    assert vector["plaintext"] == json.dumps({"url": PINNED_VECTOR_URL, "v": 1}, sort_keys=True, separators=(",", ":"))

    link = incy.decrypt_link(vector["link"], key)
    assert link.url == PINNED_VECTOR_URL
    assert link.name is None


def test_transport_tolerance_matches_the_client(key: bytes) -> None:
    link = incy.encrypt_link("https://example.com/x", key, iv=bytes(12))
    payload = link[len(incy.PREFIX) :]
    standard = base64.b64encode(b64url_decode(payload)).decode()

    for candidate in (
        link,
        f"{incy.PREFIX.upper()}{payload}",
        f"{incy.PREFIX}{payload}/",
        f"{incy.PREFIX}{standard[:20]}\r\n{standard[20:]}",
    ):
        assert incy.decrypt_link(candidate, key).url == "https://example.com/x", candidate


def test_round_trip_keeps_url_and_name(key: bytes) -> None:
    cases = [
        ("https://example.com/sub?token=abc123", None),
        ("https://example.org/sub#Remarks", "Probe Provider"),
        ("https://example.net/sub", "Имя провайдера"),
    ]
    for url, name in cases:
        link = incy.encrypt_link(url, key, name=name, iv=bytes(range(12)))
        decrypted = incy.decrypt_link(link, key)
        assert decrypted.url == url
        assert decrypted.name == name


def test_malformed_input_raises(key: bytes) -> None:
    link = incy.encrypt_link("https://example.com/x", key, iv=bytes(12))

    with pytest.raises(ValueError, match="must start with"):
        incy.decrypt_link("happ://crypt5/abc", key)
    with pytest.raises(ValueError, match="not base64"):
        incy.decrypt_payload("not base64 !!", key)
    with pytest.raises(ValueError, match="minimum is 29"):
        incy.decrypt_payload(b64url_encode(bytes(28)), key)
    with pytest.raises(ValueError, match="authentication failed"):
        incy.decrypt_link(link, bytes(32))
    with pytest.raises(ValueError, match="no non-empty url"):
        incy.decrypt_link(incy.encrypt_link("", key, iv=bytes(12)), key)

    tampered = bytearray(b64url_decode(link[len(incy.PREFIX) :]))
    tampered[-1] ^= 0x01
    with pytest.raises(ValueError, match="authentication failed"):
        incy.decrypt_payload(b64url_encode(bytes(tampered)), key)


def test_a_real_apk_yields_the_same_key() -> None:
    apk = os.environ.get(INCY_APK_ENV)
    if not apk or not Path(apk).is_file():
        pytest.skip(f"{INCY_APK_ENV} is not set to an INCY APK")

    keymat = incy.read_keymat(apk)
    assert keymat.a_sha256 == incy.KEYMAT_A_SHA256
    assert keymat.b_sha256 == incy.KEYMAT_B_SHA256
    assert incy.fingerprint(incy.derive_key(keymat)) == incy.EXPECTED_FINGERPRINT


def test_an_apk_without_the_assets_is_reported(tmp_path: Path) -> None:
    empty = tmp_path / "empty.apk"
    with zipfile.ZipFile(empty, "w"):
        pass

    with pytest.raises(IncyKeymatError, match="missing asset"):
        incy.read_keymat(empty)
