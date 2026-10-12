"""Acceptance test: byte-identical reproduction of keys.json."""

import json
from pathlib import Path

from happ_keys.extractor import Extractor


def test_acceptance_byte_identical_reproduction(apk_path: Path, ref_keys_json: Path, tmp_path: Path) -> None:
    """Primary Acceptance Criterion 1:
    Extract keys from Happ.apk and verify that produced keys.json is byte-identical
    to the reference keys.json.
    """
    out_file = tmp_path / "keys.json"
    meta_file = tmp_path / "meta.json"

    extractor = Extractor(apk_path)
    result = extractor.extract()
    result.save(out_file, meta_path=meta_file)

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
