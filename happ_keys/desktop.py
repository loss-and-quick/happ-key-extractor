"""Extraction and upstream release tracking for Happ Desktop and Incy."""

from __future__ import annotations

import io
import json
import os
import re
import struct
import tarfile
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import zstandard

from happ_keys.happ_sub import (
    HappDesktopRelease,
    IncyAndroidRelease,
    IncyDesktopRelease,
    check_happ_desktop_release,
    check_incy_android_release,
    check_incy_desktop_release,
)

HAPP_DESKTOP_REPO = "Happ-proxy/happ-desktop"
INCY_PLATFORMS_REPO = "INCY-DEV/incy-platforms"
_UA_TEMPLATE = b"Happ/%1/%2/%3%4%5\x00"
_VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+)+$")
_STAMP_RE = re.compile(r"^[0-9]{10}$")
_SUFFIX_RE = re.compile(r"^[0-9]{2}$")


class DesktopExtractError(Exception):
    """Raised when release constants cannot be extracted from desktop binaries or packages."""


def iter_ar(data_or_file: bytes | io.BytesIO) -> Iterator[tuple[str, bytes]]:
    """Iterate over members of a Debian ar archive."""
    stream = io.BytesIO(data_or_file) if isinstance(data_or_file, bytes) else data_or_file
    magic = stream.read(8)
    if magic != b"!<arch>\n":
        raise DesktopExtractError("Not a valid ar archive (bad magic header)")

    while True:
        hdr = stream.read(60)
        if len(hdr) < 60:
            break
        name = hdr[:16].strip().decode("ascii", errors="replace").rstrip("/")
        try:
            size = int(hdr[48:58].strip().decode("ascii"))
        except ValueError as exc:
            raise DesktopExtractError(f"Corrupt ar header size for {name}") from exc
        content = stream.read(size)
        if size % 2 != 0:
            _ = stream.read(1)
        yield name, content


def _open_tar(content: bytes, name: str) -> tarfile.TarFile:
    if name.endswith(".zst"):
        dctx = zstandard.ZstdDecompressor()
        decompressed = dctx.decompress(content, max_output_size=500 * 1024 * 1024)
        return tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:*")
    return tarfile.open(fileobj=io.BytesIO(content), mode="r:*")


def extract_happ_from_deb_bytes(deb_bytes: bytes) -> tuple[str | None, bytes]:
    """Extract debian package version from control and the /opt/happ/bin/Happ binary bytes."""
    control_version: str | None = None
    happ_bin: bytes | None = None

    for name, content in iter_ar(deb_bytes):
        if name.startswith("control.tar"):
            with _open_tar(content, name) as tf:
                for member in tf.getmembers():
                    if member.name in ("./control", "control"):
                        f = tf.extractfile(member)
                        if f is not None:
                            ctl_text = f.read().decode("utf-8", errors="replace")
                            vm = re.search(r"^Version:\s*([0-9A-Za-z.]+)", ctl_text, re.M)
                            if vm:
                                control_version = vm.group(1).split("-")[0]
        elif name.startswith("data.tar"):
            with _open_tar(content, name) as tf:
                for member in tf.getmembers():
                    if member.name.endswith("/Happ") or member.name == "Happ":
                        f = tf.extractfile(member)
                        if f is not None:
                            happ_bin = f.read()
                            break

    if happ_bin is None:
        raise DesktopExtractError("Could not locate Happ binary in Debian package")
    return control_version, happ_bin


def extract_happ_desktop_from_binary(
    binary_bytes: bytes,
    known_version: str | None = None,
) -> HappDesktopRelease:
    """Extract Happ Desktop version, User-Agent build stamp and suffix from the Happ ELF binary."""
    target = binary_bytes.find(_UA_TEMPLATE)
    if target == -1:
        raise DesktopExtractError("User-Agent template 'Happ/%1/%2/%3%4%5' not found in binary")

    # The 10-digit timestamp (YYMMDDHHmm) is placed immediately following the template string in .rodata
    stamp_m = re.search(rb"Happ/%1/%2/%3%4%5\x00([0-9]{10})\x00", binary_bytes)
    stamp = stamp_m.group(1).decode("ascii") if stamp_m else None

    # Search for RIP-relative LEA instructions targeting the template
    func_candidates: list[int] = []
    lea_prefixes = (
        b"\x48\x8d\x15",
        b"\x4c\x8d\x15",
        b"\x48\x8d\x0d",
        b"\x48\x8d\x35",
        b"\x4c\x8d\x0d",
        b"\x4c\x8d\x35",
    )
    for i in range(len(binary_bytes) - 7):
        if binary_bytes[i : i + 3] in lea_prefixes:
            disp = struct.unpack("<i", binary_bytes[i + 3 : i + 7])[0]
            if i + 7 + disp == target:
                func_candidates.append(i)

    version = known_version
    suffix: str | None = None

    for lea_off in func_candidates:
        chunk = binary_bytes[lea_off : lea_off + 600]
        strings_in_order: list[str] = []
        for j in range(len(chunk) - 7):
            b = chunk[j]
            if (b & 0xF0) == 0x40 and chunk[j + 1] == 0x8D and (chunk[j + 2] & 0xC7) == 0x05:
                disp = struct.unpack("<i", chunk[j + 3 : j + 7])[0]
                ins_len = 7
            elif b == 0x8D and (chunk[j + 1] & 0xC7) == 0x05:
                disp = struct.unpack("<i", chunk[j + 2 : j + 6])[0]
                ins_len = 6
            else:
                continue
            rip = lea_off + j + ins_len
            addr = rip + disp
            if 0 <= addr < len(binary_bytes):
                null_pos = binary_bytes.find(b"\x00", addr)
                if null_pos != -1 and 0 < (null_pos - addr) <= 32:
                    val = binary_bytes[addr:null_pos].decode("ascii", errors="ignore")
                    strings_in_order.append(val)

        for s in strings_in_order:
            if _VERSION_RE.match(s) and len(s) <= 10:
                if version is None or version == s:
                    version = s
            elif _STAMP_RE.match(s):
                stamp = s
            elif _SUFFIX_RE.match(s):
                suffix = s

    if version is None:
        raise DesktopExtractError("Could not determine Happ Desktop version from binary")
    if stamp is None:
        raise DesktopExtractError("Could not determine Happ Desktop User-Agent build stamp from binary")
    if suffix is None:
        raise DesktopExtractError("Could not determine Happ Desktop User-Agent suffix from binary")

    release = HappDesktopRelease(version=version, ua_build_stamp=stamp, ua_suffix=suffix)
    check_happ_desktop_release(release)
    return release


def extract_happ_desktop_from_deb(deb_path: Path | str) -> HappDesktopRelease:
    """Extract Happ Desktop release constants from a Debian package file."""
    path = Path(deb_path)
    if not path.is_file():
        raise DesktopExtractError(f"Debian package file not found: {path}")
    deb_bytes = path.read_bytes()
    control_version, happ_bin = extract_happ_from_deb_bytes(deb_bytes)
    return extract_happ_desktop_from_binary(happ_bin, known_version=control_version)


def github_api_get(endpoint: str, token: str | None = None) -> Any:
    """Make an authenticated GET request to the GitHub API."""
    url = endpoint if endpoint.startswith("http") else f"https://api.github.com/{endpoint.lstrip('/')}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "happ-key-extractor",
            "Accept": "application/vnd.github+json",
        },
    )
    auth_token = token or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if auth_token:
        req.add_header("Authorization", f"Bearer {auth_token}")

    try:
        with urllib.request.urlopen(req, timeout=30.0) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise DesktopExtractError(f"GitHub API error {exc.code} for {url}: {body}") from exc
    except Exception as exc:
        raise DesktopExtractError(f"Network error contacting GitHub API {url}: {exc}") from exc


def download_asset(url: str, dest_path: Path, token: str | None = None) -> Path:
    """Download a release asset with optional authentication."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "happ-key-extractor",
            "Accept": "application/octet-stream",
        },
    )
    auth_token = token or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if auth_token:
        req.add_header("Authorization", f"Bearer {auth_token}")
    try:
        with urllib.request.urlopen(req, timeout=300.0) as resp, open(dest_path, "wb") as out:
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                _ = out.write(chunk)
    except Exception as exc:
        raise DesktopExtractError(f"Failed to download asset from {url}: {exc}") from exc
    return dest_path


def fetch_latest_happ_desktop_release(token: str | None = None) -> dict[str, Any]:
    """Fetch the latest release information for Happ Desktop from GitHub Releases."""
    data = github_api_get(f"repos/{HAPP_DESKTOP_REPO}/releases/latest", token=token)
    tag_name = str(data.get("tag_name", "")).lstrip("v")
    assets: list[dict[str, Any]] = data.get("assets", [])

    # Look for Linux x64 deb package
    deb_asset = next((a for a in assets if str(a.get("name", "")) == "Happ.linux.x64.deb"), None)
    if not deb_asset:
        deb_asset = next((a for a in assets if str(a.get("name", "")).endswith(".deb")), None)

    return {
        "tag_name": data.get("tag_name"),
        "version": tag_name,
        "name": data.get("name"),
        "deb_asset": {
            "name": deb_asset.get("name"),
            "url": deb_asset.get("browser_download_url"),
            "size": deb_asset.get("size"),
            "digest": deb_asset.get("digest"),
        }
        if deb_asset
        else None,
        "html_url": data.get("html_url"),
    }


def parse_incy_android_tag(tag: str) -> tuple[str, int]:
    """Extract version and versionCode from an Incy android release tag, e.g. android-v3.7.0 -> ('3.7.0', 370)."""
    raw = tag.removeprefix("android-v").removeprefix("android-").lstrip("v")
    parts = raw.split(".")
    try:
        if len(parts) >= 3:
            code = int(parts[0]) * 100 + int(parts[1]) * 10 + int(parts[2])
        elif len(parts) == 2:
            code = int(parts[0]) * 100 + int(parts[1]) * 10
        else:
            code = int(parts[0])
    except ValueError as exc:
        raise DesktopExtractError(f"Cannot derive versionCode from Incy tag {tag}") from exc
    return raw, code


def parse_incy_desktop_tag(tag: str) -> str:
    """Extract version from an Incy desktop release tag, e.g. desktop-v3.8.10 -> '3.8.10'."""
    return tag.removeprefix("desktop-v").removeprefix("desktop-").lstrip("v")


def fetch_latest_incy_releases(token: str | None = None) -> dict[str, Any]:
    """Fetch the latest Android and Desktop release tags for Incy from INCY-DEV/incy-platforms."""
    releases: list[dict[str, Any]] = github_api_get(f"repos/{INCY_PLATFORMS_REPO}/releases", token=token)

    latest_android: IncyAndroidRelease | None = None
    android_asset: dict[str, Any] | None = None
    latest_desktop: IncyDesktopRelease | None = None
    desktop_asset: dict[str, Any] | None = None

    for rel in releases:
        tag = str(rel.get("tag_name", ""))
        assets = rel.get("assets", [])
        if latest_android is None and tag.startswith("android-"):
            ver, code = parse_incy_android_tag(tag)
            latest_android = IncyAndroidRelease(version=ver, version_code=code)
            check_incy_android_release(latest_android)
            apk_ast = next((a for a in assets if str(a.get("name", "")).endswith(".apk")), None)
            if apk_ast:
                android_asset = {
                    "name": apk_ast.get("name"),
                    "url": apk_ast.get("browser_download_url"),
                    "size": apk_ast.get("size"),
                }
        elif latest_desktop is None and tag.startswith("desktop-"):
            ver = parse_incy_desktop_tag(tag)
            latest_desktop = IncyDesktopRelease(version=ver)
            check_incy_desktop_release(latest_desktop)
            zip_ast = next((a for a in assets if str(a.get("name", "")).endswith(".zip")), None)
            if zip_ast:
                desktop_asset = {
                    "name": zip_ast.get("name"),
                    "url": zip_ast.get("browser_download_url"),
                    "size": zip_ast.get("size"),
                }
        if latest_android is not None and latest_desktop is not None:
            break

    return {
        "android": latest_android,
        "android_asset": android_asset,
        "desktop": latest_desktop,
        "desktop_asset": desktop_asset,
    }
