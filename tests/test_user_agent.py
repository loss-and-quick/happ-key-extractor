"""User-Agent release constants read from the builder method of each pinned release."""

from collections.abc import Callable
from pathlib import Path

import pytest
from androguard.core.apk import APK
from androguard.core.dex import DEX

from happ_keys.user_agent import UserAgentRelease, check_user_agent_builder, find_user_agent_release


@pytest.mark.parametrize(
    ("version", "version_code", "stamp", "suffix"),
    [
        ("4.7.1", 1703, "1791210317680", "50"),
        ("4.5.0", 1679, "1790239623017", "35"),
        ("4.3.0", 1643, "1787840862247", "38"),
        # Extraction rejects 3.26.3, but its User-Agent builder has the same shape.
        ("3.26.3", 1567, "1783943383683", "36"),
    ],
)
def test_user_agent_release(
    version: str, version_code: int, stamp: str, suffix: str, happ_apk: Callable[[str], Path]
) -> None:
    apk = APK(str(happ_apk(version)))
    dex = [DEX(b) for b in apk.get_all_dex()]
    assert (apk.get_androidversion_name(), int(apk.get_androidversion_code())) == (version, version_code)

    assert find_user_agent_release(dex, version, version_code) == UserAgentRelease(version, version_code, stamp, suffix)


def test_user_agent_release_cross_checks_manifest(apk_path: Path) -> None:
    dex = [DEX(b) for b in APK(str(apk_path)).get_all_dex()]
    with pytest.raises(ValueError, match=r"manifest versionName is 9\.9\.9"):
        find_user_agent_release(dex, "9.9.9", 1703)
    with pytest.raises(ValueError, match="without a '<stamp>1' seed"):
        find_user_agent_release(dex, "4.7.1", 1)


def test_missing_builder_is_a_warning() -> None:
    release, check = check_user_agent_builder([], "4.7.1", 1703)

    assert release is None
    assert (check.passed, check.is_warning) == (False, True)
    assert check.error == "expected one Happ/4.7.1/ User-Agent builder, found 0"
