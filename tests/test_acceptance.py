"""Acceptance test: byte-identical reproduction of keys.json."""

import base64
import hashlib
import json
from pathlib import Path

from androguard.core.apk import APK

from happ_keys import happ_sub
from happ_keys.apk_signer import get_ssaid_signers
from happ_keys.extractor import Extractor

HAPP_CERT_SHA256 = "397e98abed03c5f263ffaf4e8a1043b2a59f538b99e75cf152fa05a7e8007d8d"
SIGNERS_RS = Path(__file__).parent / "data" / "happ-sub" / "src" / "device" / "signers.rs"


def test_acceptance_byte_identical_reproduction(apk_path: Path, ref_keys_json: Path, tmp_path: Path) -> None:
    """Primary Acceptance Criterion 1:
    Extract keys from Happ.apk and verify that produced keys.json is byte-identical
    to the reference keys.json.
    """
    out_file = tmp_path / "keys.json"
    meta_file = tmp_path / "meta.json"
    signers_file = tmp_path / "signers.json"

    extractor = Extractor(apk_path)
    result = extractor.extract()
    result.save(out_file, meta_path=meta_file, signers_path=signers_file)

    # 1. Byte-level equality
    produced_bytes = out_file.read_bytes()
    expected_bytes = ref_keys_json.read_bytes()
    assert produced_bytes == expected_bytes, "Produced keys.json is not byte-identical to reference keys.json"

    # 2. JSON structural equality
    produced_obj = json.loads(produced_bytes)
    expected_obj = json.loads(expected_bytes)
    assert produced_obj == expected_obj
    assert len(produced_obj) == 90

    # 3. All critical verification checks must have passed
    assert result.report.all_passed is True
    assert result.report.warnings_count == 0

    # 4. The signer export is what happ-sub embeds as HAPP_SIGNERS
    signers = json.loads(signers_file.read_text(encoding="utf-8"))
    assert signers["scheme"] == "v2"
    assert signers["apk_version"] == "4.7.1"
    assert signers["sha256"] == [HAPP_CERT_SHA256]
    assert hashlib.sha256(base64.b64decode(signers["certs"][0])).hexdigest() == HAPP_CERT_SHA256


def test_ssaid_signers_471(apk_path: Path) -> None:
    """Happ 4.7.1 carries only a v2 block with one 782-byte certificate."""
    scheme, certs = get_ssaid_signers(APK(str(apk_path)))

    assert scheme == "v2"
    assert len(certs) == 1
    assert len(certs[0]) == 782
    assert hashlib.sha256(certs[0]).hexdigest() == HAPP_CERT_SHA256
    # Regenerating happ-sub's signers.rs from the APK reproduces it byte for byte.
    rendered = happ_sub.render_signers_rs(happ_sub.Signers(scheme=scheme, certs=tuple(certs), apk_version="4.7.1"))
    assert rendered == SIGNERS_RS.read_text(encoding="utf-8")
