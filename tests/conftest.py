"""Shared fixtures. Release APKs come from a local cache filled by `happ_keys fetch-apks`."""

from __future__ import annotations

import functools
import os
from collections.abc import Callable
from pathlib import Path

import pytest

from happ_keys import apks

ROOT_DIR = Path(__file__).parent.parent
DATA_DIR = ROOT_DIR / "tests" / "data"
REFERENCE_KEYS_JSON = DATA_DIR / "keys.json"
REFERENCE_KEYS_RAW = DATA_DIR / "keys-raw.tsv"

APK_CACHE_ENV = "HAPP_APK_CACHE"
# CI sets this so a missing APK fails the run instead of silently skipping the extraction tests.
REQUIRE_APKS_ENV = "HAPP_REQUIRE_APKS"

PRIMARY_VERSION = "4.7.1"


def _unavailable(reason: str) -> None:
    if os.environ.get(REQUIRE_APKS_ENV) == "1":
        pytest.fail(reason)
    pytest.skip(reason)


@functools.cache
def _manifest() -> dict[str, apks.PinnedApk]:
    return apks.load_manifest()


@functools.cache
def _verified_apk(version: str, cache_dir: str) -> Path | str:
    entry = _manifest()[version]
    path = entry.cache_path(Path(cache_dir))
    if not path.is_file():
        return f"Happ {version} APK not found at {path}; run `python -m happ_keys fetch-apks --dest {cache_dir}`"
    if not apks.is_cached(entry, Path(cache_dir)):
        pytest.fail(f"{path} does not match the pinned sha256 {entry.sha256}; delete it and fetch again")
    return path


def resolve_apk(version: str) -> Path:
    cache_dir = os.environ.get(APK_CACHE_ENV)
    if not cache_dir:
        _unavailable(
            f"{APK_CACHE_ENV} is not set; run `python -m happ_keys fetch-apks --dest <dir>` "
            f"and export {APK_CACHE_ENV}=<dir>"
        )
    result = _verified_apk(version, str(Path(cache_dir).resolve()))
    if isinstance(result, str):
        _unavailable(result)
    assert isinstance(result, Path)
    return result


@pytest.fixture
def happ_apk() -> Callable[[str], Path]:
    """Return a resolver from Happ version to the cached, sha256-verified APK path."""
    return resolve_apk


@pytest.fixture
def apk_path() -> Path:
    return resolve_apk(PRIMARY_VERSION)


@pytest.fixture
def ref_keys_json() -> Path:
    return REFERENCE_KEYS_JSON


@pytest.fixture
def ref_keys_raw() -> Path:
    return REFERENCE_KEYS_RAW
