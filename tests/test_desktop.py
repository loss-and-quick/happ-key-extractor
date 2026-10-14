import shutil
from pathlib import Path

import pytest

from happ_keys import desktop, happ_sub
from happ_keys.cli import main

SNAPSHOT_DIR = Path(__file__).parent / "data" / "happ-sub"


@pytest.fixture
def happ_sub_repo(tmp_path: Path) -> Path:
    return Path(shutil.copytree(SNAPSHOT_DIR, tmp_path / "happ-sub"))


@pytest.mark.skipif(not Path("/home/minicx/Downloads/Happ.linux.x64.deb").is_file(), reason="local sample deb missing")
def test_extract_happ_desktop_from_deb_sample() -> None:
    release = desktop.extract_happ_desktop_from_deb("/home/minicx/Downloads/Happ.linux.x64.deb")
    assert release == happ_sub.HappDesktopRelease(
        version="4.5.4",
        ua_build_stamp="2610141140",
        ua_suffix="85",
        bundle_id_linux="su.happ.desktop.linux",
        api_version="1.0",
    )


def test_parse_incy_tags() -> None:
    assert desktop.parse_incy_android_tag("android-v3.7.0") == ("3.7.0", 370)
    assert desktop.parse_incy_desktop_tag("desktop-v3.8.10") == "3.8.10"


def test_release_sync_updates_release_rs(happ_sub_repo: Path, tmp_path: Path) -> None:
    pr_body = tmp_path / "pr.md"
    code = main(
        [
            "release-sync",
            "--repo",
            str(happ_sub_repo),
            "--incy-version",
            "3.8.0",
            "--incy-version-code",
            "380",
            "--incy-desktop-version",
            "3.8.11",
            "--write",
            "--pr-body",
            str(pr_body),
        ]
    )
    assert code == 0
    release = happ_sub.load_release(happ_sub_repo)
    assert release.incy == happ_sub.IncyAndroidRelease(version="3.8.0", version_code=380)
    assert release.incy_desktop == happ_sub.IncyDesktopRelease(version="3.8.11")
    assert "Incy Android" in pr_body.read_text(encoding="utf-8")
    assert "Incy Desktop" in pr_body.read_text(encoding="utf-8")
