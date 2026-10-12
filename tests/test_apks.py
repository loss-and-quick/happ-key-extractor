"""APK manifest consistency and the verified download path (offline, via file:// URLs)."""

import hashlib
import re
import zipfile
from pathlib import Path

import pytest

from happ_keys import apks

RELEASE_URL = "https://github.com/Happ-proxy/happ-android/releases/download/{version}/{asset}"


def test_manifest_pins_the_tested_versions() -> None:
    manifest = apks.load_manifest()

    assert set(manifest) == {"4.7.1", "4.5.0", "4.3.0", "3.26.3"}
    for version, entry in manifest.items():
        assert entry.version == version
        assert entry.url == RELEASE_URL.format(version=version, asset=entry.asset)
        assert re.fullmatch(r"[0-9a-f]{64}", entry.sha256)
        assert entry.size > 0


def _pinned(tmp_path: Path, payload: bytes, sha256: str | None = None) -> apks.PinnedApk:
    source = tmp_path / "upstream.apk"
    source.write_bytes(payload)
    return apks.PinnedApk(
        version="9.9.9",
        asset="Happ.apk",
        url=source.as_uri(),
        size=len(payload),
        sha256=sha256 or hashlib.sha256(payload).hexdigest(),
    )


def test_fetch_downloads_and_reuses_verified_cache(tmp_path: Path) -> None:
    entry = _pinned(tmp_path, b"apk-bytes")
    cache = tmp_path / "cache"

    path = apks.fetch_apk(entry, cache)
    assert path == cache / "9.9.9" / "Happ.apk"
    assert path.read_bytes() == b"apk-bytes"

    # A verified cache entry must not touch the network again.
    unreachable = apks.PinnedApk(**{**entry.__dict__, "url": (tmp_path / "gone.apk").as_uri()})
    assert apks.fetch_apk(unreachable, cache, retries=1) == path


def test_fetch_rejects_digest_mismatch(tmp_path: Path) -> None:
    entry = _pinned(tmp_path, b"tampered", sha256="0" * 64)
    cache = tmp_path / "cache"

    with pytest.raises(apks.FetchError, match="sha256 mismatch"):
        apks.fetch_apk(entry, cache)
    assert not any(cache.rglob("*.apk*"))


def test_fetch_reports_unreachable_source(tmp_path: Path) -> None:
    entry = apks.PinnedApk("9.9.9", "Happ.apk", (tmp_path / "missing.apk").as_uri(), 1, "0" * 64)

    with pytest.raises(apks.FetchError, match="failed after 1 attempts"):
        apks.fetch_apk(entry, tmp_path / "cache", retries=1)


def test_read_native_lib(tmp_path: Path) -> None:
    apk = tmp_path / "Happ.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr(apks.NATIVE_LIB_PATH, b"\x7fELF")
    assert apks.read_native_lib(apk) == b"\x7fELF"
