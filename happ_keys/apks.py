"""Pinned Happ release APKs: manifest loading, verified download and cache layout."""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MANIFEST: Path = Path(__file__).resolve().parent.parent / "tests" / "apks.json"
NATIVE_LIB_PATH: str = "lib/arm64-v8a/liberror-code.so"

_CHUNK = 1 << 20


class FetchError(Exception):
    """Raised when an APK cannot be downloaded or does not match its pinned digest."""


@dataclass(frozen=True)
class PinnedApk:
    version: str
    asset: str
    url: str
    size: int
    sha256: str

    def cache_path(self, cache_dir: Path) -> Path:
        return cache_dir / self.version / self.asset


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, PinnedApk]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return {
        version: PinnedApk(
            version=version,
            asset=entry["asset"],
            url=entry["url"],
            size=int(entry["size"]),
            sha256=entry["sha256"].lower(),
        )
        for version, entry in doc["apks"].items()
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def is_cached(apk: PinnedApk, cache_dir: Path) -> bool:
    path = apk.cache_path(cache_dir)
    return path.is_file() and path.stat().st_size == apk.size and sha256_file(path) == apk.sha256


def _download(url: str, dest: Path, *, read_timeout: float, max_time: float) -> None:
    deadline = time.monotonic() + max_time
    request = urllib.request.Request(url, headers={"User-Agent": "happ-key-extractor"})
    with urllib.request.urlopen(request, timeout=read_timeout) as resp, dest.open("wb") as out:
        while chunk := resp.read(_CHUNK):
            out.write(chunk)
            if time.monotonic() > deadline:
                raise TimeoutError(f"download exceeded {max_time:.0f}s")


def fetch_apk(
    apk: PinnedApk,
    cache_dir: Path,
    *,
    retries: int = 3,
    read_timeout: float = 60.0,
    max_time: float = 900.0,
) -> Path:
    """Ensure the pinned APK is in the cache, downloading it if needed. Returns its path."""
    target = apk.cache_path(cache_dir)
    if is_cached(apk, cache_dir):
        return target

    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + ".part")
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            _download(apk.url, partial, read_timeout=read_timeout, max_time=max_time)
            break
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            partial.unlink(missing_ok=True)
            if attempt < retries:
                time.sleep(5 * attempt)
    else:
        raise FetchError(f"{apk.version}: download of {apk.url} failed after {retries} attempts: {last_error}")

    actual = sha256_file(partial)
    if actual != apk.sha256:
        partial.unlink(missing_ok=True)
        raise FetchError(f"{apk.version}: sha256 mismatch for {apk.url}: got {actual}, pinned {apk.sha256}")
    partial.replace(target)
    return target


def read_native_lib(apk_path: Path) -> bytes:
    """Read the arm64 liberror-code.so straight from the APK zip."""
    with zipfile.ZipFile(apk_path) as zf:
        return zf.read(NATIVE_LIB_PATH)
