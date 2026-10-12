"""Extraction across the pinned release range: 4.3.0..4.7.1 share one table, 3.26.3 is rejected."""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from happ_keys.apks import read_native_lib
from happ_keys.extractor import Extractor
from happ_keys.native import UnicornNativeDumper, UnsupportedCodeShapeError


@pytest.mark.parametrize(
    ("version", "patch_offset"),
    [
        ("4.7.1", 0x18E0DC),
        ("4.5.0", 0x18E0DC),
        ("4.3.0", 0x18E3EC),
    ],
)
def test_supported_versions_produce_reference_table(
    version: str,
    patch_offset: int,
    happ_apk: Callable[[str], Path],
    ref_keys_json: Path,
) -> None:
    result = Extractor(happ_apk(version)).extract()

    assert result.meta["app_version"] == version
    assert result.meta["patch_offset"] == hex(patch_offset)
    assert result.report.all_passed is True
    assert result.report.checks["key_table_shape"].details["key_count"] == 90
    assert json.dumps(result.keys, indent=2, sort_keys=True) == ref_keys_json.read_text(encoding="utf-8")


def test_legacy_version_3263_is_rejected(happ_apk: Callable[[str], Path]) -> None:
    """Pre-4.3 builds use a different JNI epilogue (`blr x8`) and a 10-key table."""
    apk = happ_apk("3.26.3")

    with pytest.raises(UnsupportedCodeShapeError):
        UnicornNativeDumper(read_native_lib(apk))

    with pytest.raises((UnsupportedCodeShapeError, ValueError)):
        Extractor(apk).extract()
