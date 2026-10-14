"""Read and extend the body key tables and signer certificates of the happ-sub Rust crate.

happ-sub keeps each key generation in `src/keys/gen<N>.rs` as a `KEYS_GEN<N>` slice of
`(&str, &[u8; 16])` pairs and registers it in `src/keys/mod.rs` as a `KeyTable` const listed
in `ALL_TABLES`, newest first. Body keys carry no version on the wire, so a table extracted
from a new APK either equals an existing generation or becomes the next one.

`src/device/signers.rs` holds Happ's APK signer certificates as `HAPP_SIGNERS`; happ-sub derives
Happ's SSAID from them. A new certificate replaces the file and the cert-derived test pins in
`src/device/mod.rs`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

KEYS_DIR = Path("src") / "keys"
DEVICE_DIR = Path("src") / "device"

# rustfmt keeps an array on one line only while it fits `array_width` (60% of max_width 100).
_RUSTFMT_MAX_WIDTH = 100
_RUSTFMT_ARRAY_WIDTH = 60

_GEN_FILE_RE = re.compile(r"^gen(\d+)\.rs$")
_TABLE_HEADER_RE = re.compile(
    r"pub\s+const\s+KEYS_GEN(?P<gen>\d+)\s*:\s*&\s*\[\s*\(\s*&\s*str\s*,\s*&\s*\[\s*u8\s*;\s*16\s*\]\s*\)\s*\]\s*=\s*&\s*\["
)
_ENTRY_RE = re.compile(r'\(\s*"(?P<id>key\d{2})"\s*,\s*b"(?P<lit>(?:[^"\\]|\\.)*)"\s*,?\s*\)\s*,?', re.S)
_SKIP_RE = re.compile(r"(?:\s+|//[^\n]*|/\*.*?\*/)+", re.S)
_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.]*$")

_SIMPLE_ESCAPES = {"\\": 0x5C, '"': 0x22, "'": 0x27, "n": 0x0A, "r": 0x0D, "t": 0x09, "0": 0x00}

KeyTableEntries = tuple[tuple[str, bytes], ...]


class HappSubFormatError(Exception):
    """Raised when happ-sub sources do not have the layout the generator relies on."""


@dataclass(frozen=True)
class RustKeyTable:
    generation: int
    entries: KeyTableEntries

    def as_dict(self) -> dict[str, bytes]:
        return dict(self.entries)


def unescape_byte_string(literal: str) -> bytes:
    """Decode the body of a Rust byte string literal `b"..."`."""
    out = bytearray()
    i = 0
    while i < len(literal):
        ch = literal[i]
        if ch != "\\":
            if ord(ch) > 0x7F:
                raise HappSubFormatError(f"non-ASCII character {ch!r} in byte string")
            out.append(ord(ch))
            i += 1
            continue
        esc = literal[i + 1 : i + 2]
        if esc in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[esc])
            i += 2
        elif esc == "x":
            out.append(int(literal[i + 2 : i + 4], 16))
            i += 4
        elif esc == "\n":
            i += 2
            while i < len(literal) and literal[i] in " \t\r\n":
                i += 1
        else:
            raise HappSubFormatError(f"unsupported escape \\{esc} in byte string")
    return bytes(out)


def escape_byte_string(data: bytes) -> str:
    """Encode bytes as the body of a Rust byte string literal, printable ASCII kept verbatim."""
    parts: list[str] = []
    for b in data:
        if b == 0x5C:
            parts.append("\\\\")
        elif b == 0x22:
            parts.append('\\"')
        elif 0x20 <= b < 0x7F:
            parts.append(chr(b))
        else:
            parts.append(f"\\x{b:02x}")
    return "".join(parts)


def parse_key_table(source: str) -> RustKeyTable:
    """Parse the single `KEYS_GEN<N>` table declared in a `gen<N>.rs` source file."""
    headers = list(_TABLE_HEADER_RE.finditer(source))
    if len(headers) != 1:
        raise HappSubFormatError(f"expected one KEYS_GEN<N> table, found {len(headers)}")
    header = headers[0]

    entries: list[tuple[str, bytes]] = []
    pos = header.end()
    while True:
        skip = _SKIP_RE.match(source, pos)
        if skip:
            pos = skip.end()
        if source.startswith("]", pos):
            break
        entry = _ENTRY_RE.match(source, pos)
        if entry is None:
            snippet = source[pos : pos + 40].splitlines()[0] if pos < len(source) else "<eof>"
            raise HappSubFormatError(f"unexpected token in key table at offset {pos}: {snippet!r}")
        entries.append((entry["id"], unescape_byte_string(entry["lit"])))
        pos = entry.end()

    ids = [kid for kid, _ in entries]
    if len(set(ids)) != len(ids):
        raise HappSubFormatError("duplicate key ids in table")
    for kid, key in entries:
        if len(key) != 16:
            raise HappSubFormatError(f"{kid} is {len(key)} bytes, expected 16")
    return RustKeyTable(generation=int(header["gen"]), entries=tuple(entries))


def load_tables(repo: Path) -> list[RustKeyTable]:
    """Load every `src/keys/gen<N>.rs` table of a happ-sub checkout, oldest first."""
    keys_dir = repo / KEYS_DIR
    tables: list[RustKeyTable] = []
    for path in sorted(keys_dir.iterdir()):
        m = _GEN_FILE_RE.match(path.name)
        if not m:
            continue
        table = parse_key_table(path.read_text(encoding="utf-8"))
        if table.generation != int(m.group(1)):
            raise HappSubFormatError(f"{path.name} declares KEYS_GEN{table.generation}")
        tables.append(table)
    if not tables:
        raise HappSubFormatError(f"no gen<N>.rs tables under {keys_dir}")
    return sorted(tables, key=lambda t: t.generation)


def table_from_keys_json(keys: Mapping[str, str]) -> KeyTableEntries:
    """Convert extractor output (`{"key01": "key01:..."}`) into ordered table entries."""
    return tuple((kid, keys[kid].encode("utf-8")) for kid in sorted(keys))


def table_sha256(entries: Iterable[tuple[str, bytes]]) -> str:
    canonical = "".join(f"{kid}:{key.hex()}\n" for kid, key in sorted(entries))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def find_matching_table(entries: KeyTableEntries, tables: Iterable[RustKeyTable]) -> RustKeyTable | None:
    wanted = dict(entries)
    return next((t for t in tables if t.as_dict() == wanted), None)


def _check_version(version: str) -> None:
    if not _VERSION_RE.match(version):
        raise HappSubFormatError(f"refusing to use {version!r} as a table version")


def table_ident(generation: int, version: str) -> str:
    _check_version(version)
    return f"TABLE_GEN{generation}_{re.sub(r'[^0-9A-Za-z]', '_', version).upper()}"


def table_id(generation: int, version: str) -> str:
    _check_version(version)
    return f"gen{generation}-{version}"


def render_gen_rs(generation: int, label: str, entries: KeyTableEntries) -> str:
    """Render `gen<N>.rs` in the layout of the hand-written gen1.rs."""
    lines = [
        f"/// {len(entries)} AES-128 keys for Generation {generation} ({label}).",
        f"pub const KEYS_GEN{generation}: &[(&str, &[u8; 16])] = &[",
    ]
    for kid, key in entries:
        if len(key) != 16:
            raise HappSubFormatError(f"{kid} is {len(key)} bytes, expected 16")
        lines.append(f'    ("{kid}", b"{escape_byte_string(key)}"),')
    lines.append("];")
    return "\n".join(lines) + "\n"


def _insert_after_last(text: str, pattern: str, addition: str, what: str) -> str:
    matches = list(re.finditer(pattern, text, re.M | re.S))
    if not matches:
        raise HappSubFormatError(f"mod.rs: cannot find {what}")
    end = matches[-1].end()
    return text[:end] + addition + text[end:]


def _render_all_tables(items: list[str]) -> str:
    prefix = "pub const ALL_TABLES: &[&KeyTable] = &"
    array = "[" + ", ".join(items) + "]"
    if len(array) <= _RUSTFMT_ARRAY_WIDTH and len(prefix) + len(array) + 1 <= _RUSTFMT_MAX_WIDTH:
        return f"{prefix}{array};"
    body = "".join(f"    {item},\n" for item in items)
    return f"{prefix}[\n{body}];"


def register_table(mod_rs: str, generation: int, version: str) -> str:
    """Add `gen<N>` to mod.rs: module, re-export, `KeyTable` const, and head of `ALL_TABLES`."""
    ident = table_ident(generation, version)
    if re.search(rf"^mod gen{generation};$", mod_rs, re.M):
        raise HappSubFormatError(f"mod.rs already declares gen{generation}")

    text = _insert_after_last(mod_rs, r"^mod gen\d+;\n", f"mod gen{generation};\n", "`mod gen<N>;`")
    text = _insert_after_last(
        text,
        r"^pub use gen\d+::KEYS_GEN\d+;\n",
        f"pub use gen{generation}::KEYS_GEN{generation};\n",
        "`pub use gen<N>::KEYS_GEN<N>;`",
    )
    block = (
        f"\n/// Key table for Generation {generation} (measured in Happ {version}).\n"
        f"pub const {ident}: KeyTable = KeyTable {{\n"
        f'    id: "{table_id(generation, version)}",\n'
        f"    entries: KEYS_GEN{generation},\n"
        "};\n"
    )
    text = _insert_after_last(
        text,
        r"^pub const TABLE_GEN\d+\w*: KeyTable = KeyTable \{.*?^\};\n",
        block,
        "a `pub const TABLE_GEN<N>_...: KeyTable` block",
    )

    all_re = re.compile(r"^pub const ALL_TABLES: &\[&KeyTable\] = &\[(?P<items>.*?)\];", re.M | re.S)
    m = all_re.search(text)
    if m is None:
        raise HappSubFormatError("mod.rs: cannot find `ALL_TABLES`")
    items = [item.strip() for item in m["items"].split(",") if item.strip()]
    return text[: m.start()] + _render_all_tables([f"&{ident}", *items]) + text[m.end() :]


# Scheme names as `signers.json` spells them, mapped to happ-sub's `SigScheme` variants.
SIG_SCHEMES: dict[str, tuple[str, str]] = {
    "v1": ("V1", "JAR signing"),
    "v2": ("V2", "APK Signature Scheme v2"),
    "v3": ("V3", "APK Signature Scheme v3"),
    "v3.1": ("V31", "APK Signature Scheme v3.1"),
}
_SCHEME_BY_IDENT = {ident: name for name, (ident, _) in SIG_SCHEMES.items()}
_COUNT_WORDS = ("no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine")
# Each certificate array is `#[rustfmt::skip]`, laid out 16 bytes per line.
_CERT_BYTES_PER_LINE = 16

_SIGNERS_HEADER = (
    "//! Generated by happ-key-extractor from the Happ release APK. Do not edit by hand.\n"
    "\n"
    "use super::{SigScheme, SignerSet};\n"
)
_HAPP_SIGNERS_RE = re.compile(
    r"pub\s+const\s+HAPP_SIGNERS\s*:\s*SignerSet\s*=\s*SignerSet\s*\{(?P<body>.*?)\}\s*;", re.S
)
_SCHEME_FIELD_RE = re.compile(r"\bscheme\s*:\s*SigScheme::(?P<ident>\w+)\s*,")
_CERTS_FIELD_RE = re.compile(r"\bcerts\s*:\s*&\s*\[(?P<items>[^\]]*)\]")
_VERSION_FIELD_RE = re.compile(r'\bapk_version\s*:\s*"(?P<version>[^"\\]*)"')
_CERT_CONST_RE = re.compile(
    r"(?:///\s*DER, SHA-256 (?P<sha>[0-9a-f]{64})\.\s*)?(?:#\[rustfmt::skip\]\s*)?"
    r"const\s+(?P<name>CERT_\d+)\s*:\s*\[\s*u8\s*;\s*(?P<len>\d+)\s*\]\s*=\s*\[(?P<body>[^\]]*)\]\s*;"
)
_BYTE_TOKEN_RE = re.compile(r"^(?:0x[0-9a-fA-F]{1,2}|[0-9]{1,3})(?:u8)?$")


@dataclass(frozen=True)
class Signers:
    """Signer certificates of one APK: the scheme Android takes them from and the DERs in order."""

    scheme: str
    certs: tuple[bytes, ...]
    apk_version: str

    def sha256(self) -> list[str]:
        return [hashlib.sha256(der).hexdigest() for der in self.certs]


def _check_scheme(scheme: str) -> None:
    if scheme not in SIG_SCHEMES:
        raise HappSubFormatError(f"unknown signature scheme {scheme!r}")


def signers_from_json(doc: Mapping[str, Any]) -> Signers:
    """Read the `signers.json` document written by `extract --signers`."""
    scheme = str(doc.get("scheme"))
    _check_scheme(scheme)
    version = str(doc.get("apk_version"))
    _check_version(version)
    try:
        certs = tuple(base64.b64decode(c, validate=True) for c in doc.get("certs", []))
    except (binascii.Error, TypeError) as exc:
        raise HappSubFormatError(f"signers.json: certificate is not base64: {exc}") from exc
    signers = Signers(scheme=scheme, certs=certs, apk_version=version)
    if not certs:
        raise HappSubFormatError("signers.json lists no certificate")
    if "sha256" in doc and list(doc["sha256"]) != signers.sha256():
        raise HappSubFormatError("signers.json: sha256 list does not match the certificates")
    return signers


def signers_sha256(signers: Signers) -> str:
    """Digest of what the SSAID depends on: the scheme and the certificates, in order."""
    canonical = f"{signers.scheme}\n" + "".join(f"{digest}\n" for digest in signers.sha256())
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _parse_byte_array(body: str, name: str) -> bytes:
    body = re.sub(r"//[^\n]*|/\*.*?\*/", "", body, flags=re.S)
    out = bytearray()
    for token in (t.strip() for t in body.split(",")):
        if not token:
            continue
        if not _BYTE_TOKEN_RE.match(token):
            raise HappSubFormatError(f"{name}: unexpected array element {token!r}")
        value = int(token.removesuffix("u8"), 0)
        if value > 0xFF:
            raise HappSubFormatError(f"{name}: {token} does not fit in u8")
        out.append(value)
    return bytes(out)


def parse_signers_rs(source: str) -> Signers:
    """Parse `HAPP_SIGNERS` and the certificate arrays it references from `signers.rs`."""
    block = _HAPP_SIGNERS_RE.search(source)
    if block is None:
        raise HappSubFormatError("signers.rs: cannot find `HAPP_SIGNERS`")
    body = block["body"]
    scheme_m = _SCHEME_FIELD_RE.search(body)
    certs_m = _CERTS_FIELD_RE.search(body)
    version_m = _VERSION_FIELD_RE.search(body)
    if scheme_m is None or certs_m is None or version_m is None:
        raise HappSubFormatError("signers.rs: `HAPP_SIGNERS` lacks scheme, certs or apk_version")
    if scheme_m["ident"] not in _SCHEME_BY_IDENT:
        raise HappSubFormatError(f"signers.rs: unknown SigScheme::{scheme_m['ident']}")

    consts: dict[str, bytes] = {}
    for m in _CERT_CONST_RE.finditer(source):
        der = _parse_byte_array(m["body"], m["name"])
        if len(der) != int(m["len"]):
            raise HappSubFormatError(f"signers.rs: {m['name']} has {len(der)} bytes, declared {m['len']}")
        if m["sha"] and hashlib.sha256(der).hexdigest() != m["sha"]:
            raise HappSubFormatError(f"signers.rs: {m['name']} does not match its documented SHA-256")
        consts[m["name"]] = der

    certs: list[bytes] = []
    for item in (i.strip() for i in certs_m["items"].split(",")):
        if not item:
            continue
        name = item.removeprefix("&").strip()
        if name not in consts:
            raise HappSubFormatError(f"signers.rs: `HAPP_SIGNERS` references undefined {item}")
        certs.append(consts[name])
    return Signers(scheme=_SCHEME_BY_IDENT[scheme_m["ident"]], certs=tuple(certs), apk_version=version_m["version"])


def _render_certs_field(items: list[str]) -> str:
    prefix = "    certs: &"
    array = "[" + ", ".join(items) + "]"
    if len(array) <= _RUSTFMT_ARRAY_WIDTH and len(prefix) + len(array) + 1 <= _RUSTFMT_MAX_WIDTH:
        return f"{prefix}{array},"
    # rustfmt packs short items (`&CERT_<n>`) several to a line within max_width.
    lines: list[str] = []
    line = ""
    for item in items:
        candidate = f"{line} {item}," if line else f"        {item},"
        if len(candidate) > _RUSTFMT_MAX_WIDTH and line:
            lines.append(line)
            candidate = f"        {item},"
        line = candidate
    lines.append(line)
    return f"{prefix}[\n" + "\n".join(lines) + "\n    ],"


def render_signers_rs(signers: Signers) -> str:
    """Render `src/device/signers.rs` in happ-sub's generated layout."""
    _check_scheme(signers.scheme)
    _check_version(signers.apk_version)
    if not signers.certs:
        raise HappSubFormatError("refusing to render a signer set without certificates")
    ident, scheme_name = SIG_SCHEMES[signers.scheme]
    count = len(signers.certs)
    noun = "certificate" if count == 1 else "certificates"
    count_text = f"{_COUNT_WORDS[count] if count < len(_COUNT_WORDS) else count} {noun}"
    parts = [
        _SIGNERS_HEADER,
        "\n",
        f"/// Signers of Happ {signers.apk_version}: {scheme_name} only, {count_text}.\n",
        "pub const HAPP_SIGNERS: SignerSet = SignerSet {\n",
        f"    scheme: SigScheme::{ident},\n",
        _render_certs_field([f"&CERT_{i}" for i in range(count)]) + "\n",
        f'    apk_version: "{signers.apk_version}",\n',
        "};\n",
    ]
    for i, der in enumerate(signers.certs):
        parts += [
            "\n",
            f"/// DER, SHA-256 {hashlib.sha256(der).hexdigest()}.\n",
            "#[rustfmt::skip]\n",
            f"const CERT_{i}: [u8; {len(der)}] = [\n",
        ]
        for off in range(0, len(der), _CERT_BYTES_PER_LINE):
            chunk = der[off : off + _CERT_BYTES_PER_LINE]
            parts.append("    " + " ".join(f"0x{b:02x}," for b in chunk) + "\n")
        parts.append("];\n")
    return "".join(parts)


def ssaid(user_key: bytes, certs: Iterable[bytes]) -> str:
    """Android's SSAID: HMAC-SHA256 over each length-prefixed certificate, first 16 hex digits."""
    mac = hmac.new(user_key, digestmod=hashlib.sha256)
    for der in certs:
        mac.update(len(der).to_bytes(4, "big"))
        mac.update(der)
    return mac.hexdigest()[:16]


def _test_fn_span(text: str, name: str) -> tuple[int, int]:
    start = text.find(f"    fn {name}() {{\n")
    end = text.find("\n    }\n", start)
    if start < 0 or end < 0:
        raise HappSubFormatError(f"device mod.rs: cannot find test `{name}`")
    return start, end


def _sub_in_span(text: str, span: tuple[int, int], pattern: str, repl: Any, what: str, count: int | None = 1) -> str:
    start, end = span
    new, n = re.subn(pattern, repl, text[start:end])
    if n == 0 or (count is not None and n != count):
        raise HappSubFormatError(f"device mod.rs: expected {count or 'some'} {what}, found {n}")
    return text[:start] + new + text[end:]


def update_device_pins(mod_rs: str, signers: Signers) -> str:
    """Rewrite the cert-derived pins in `src/device/mod.rs` tests for a new signer set.

    `signers_digest_pinned` pins the scheme, count, length and SHA-256 of the first certificate,
    and `ssaid_matches_vector` pins SSAIDs for the key `0, 1, ..., n-1`. Both follow from the
    certificates alone; a layout the patterns do not match fails rather than leaving a stale pin.
    """
    ident, _ = SIG_SCHEMES[signers.scheme]
    first = signers.certs[0]
    text = mod_rs
    span = _test_fn_span(text, "signers_digest_pinned")
    text = _sub_in_span(
        text, span, r"(assert_eq!\(HAPP_SIGNERS\.scheme, SigScheme::)\w+(\);)", rf"\g<1>{ident}\g<2>", "scheme pin"
    )
    span = _test_fn_span(text, "signers_digest_pinned")
    text = _sub_in_span(
        text,
        span,
        r"(assert_eq!\(HAPP_SIGNERS\.certs\.len\(\), )\d+(\);)",
        rf"\g<1>{len(signers.certs)}\g<2>",
        "certificate count pin",
    )
    span = _test_fn_span(text, "signers_digest_pinned")
    text = _sub_in_span(text, span, r"(assert_eq!\(cert\.len\(\), )\d+(\);)", rf"\g<1>{len(first)}\g<2>", "length pin")
    span = _test_fn_span(text, "signers_digest_pinned")
    text = _sub_in_span(text, span, r'"[0-9a-f]{64}"', f'"{hashlib.sha256(first).hexdigest()}"', "SHA-256 pin")

    def vector(m: re.Match[str]) -> str:
        key = bytes(range(int(m["len"])))
        return f'{m["call"]}"{ssaid(key, signers.certs)}"'

    span = _test_fn_span(text, "ssaid_matches_vector")
    return _sub_in_span(
        text,
        span,
        r'(?P<call>ssaid\(&test_key\((?P<len>\d+)\), &HAPP_SIGNERS\)\.unwrap\(\),\s*)"[0-9a-f]{16}"',
        vector,
        "SSAID vectors",
        count=None,
    )


def load_signers(repo: Path) -> Signers:
    return parse_signers_rs((repo / DEVICE_DIR / "signers.rs").read_text(encoding="utf-8"))


# Release constants happ-sub's User-Agent and request code identify as, one `pub const` per line.
RELEASE_RS = Path("src") / "release.rs"
_RELEASE_CONST_RE = r"^(?P<head>pub const {name}: {ty} = )(?P<value>[^;\n]*)(?P<tail>;)$"
_STR_VALUE_RE = re.compile(r'^"(?P<s>[^"\\]*)"$')
_DIGITS_RE = re.compile(r"^[0-9]+$")
_RELEASE_FIELDS = (
    ("HAPP_VERSION", "&str"),
    ("HAPP_VERSION_CODE", "u32"),
    ("HAPP_UA_BUILD_STAMP", "&str"),
    ("HAPP_UA_SUFFIX", "&str"),
)


@dataclass(frozen=True)
class HappDesktopRelease:
    """Happ Desktop release constants: version, build stamp (YYMMDDHHmm) and suffix."""

    version: str
    ua_build_stamp: str
    ua_suffix: str
    bundle_id_linux: str = "su.happ.desktop.linux"
    api_version: str = "1.0"

    def rust_values(self) -> dict[tuple[str, str], str]:
        vals = {
            ("HAPP_DESKTOP_VERSION", "&str"): f'"{self.version}"',
            ("HAPP_DESKTOP_UA_BUILD_STAMP", "&str"): f'"{self.ua_build_stamp}"',
            ("HAPP_DESKTOP_UA_SUFFIX", "&str"): f'"{self.ua_suffix}"',
        }
        if self.bundle_id_linux:
            vals[("HAPP_DESKTOP_BUNDLE_ID_LINUX", "&str")] = f'"{self.bundle_id_linux}"'
        if self.api_version:
            vals[("HAPP_API_VERSION", "&str")] = f'"{self.api_version}"'
        return vals


@dataclass(frozen=True)
class IncyAndroidRelease:
    """Incy Android release constants: version and versionCode."""

    version: str
    version_code: int

    def rust_values(self) -> dict[tuple[str, str], str]:
        return {
            ("INCY_VERSION", "&str"): f'"{self.version}"',
            ("INCY_VERSION_CODE", "u32"): str(self.version_code),
        }


@dataclass(frozen=True)
class IncyDesktopRelease:
    """Incy Desktop release constants: version."""

    version: str

    def rust_values(self) -> dict[tuple[str, str], str]:
        return {
            ("INCY_DESKTOP_VERSION", "&str"): f'"{self.version}"',
        }


@dataclass(frozen=True)
class Release:
    """What Happ's User-Agent carries for one APK: version, versionCode, build stamp and suffix.

    Optionally carries Happ Desktop and Incy releases as well.
    """

    version: str
    version_code: int
    ua_build_stamp: str
    ua_suffix: str
    desktop: HappDesktopRelease | None = None
    incy: IncyAndroidRelease | None = None
    incy_desktop: IncyDesktopRelease | None = None

    def rust_values(self) -> dict[tuple[str, str], str]:
        values = (f'"{self.version}"', str(self.version_code), f'"{self.ua_build_stamp}"', f'"{self.ua_suffix}"')
        vals = dict(zip(_RELEASE_FIELDS, values, strict=True))
        if self.desktop is not None:
            vals.update(self.desktop.rust_values())
        if self.incy is not None:
            vals.update(self.incy.rust_values())
        if self.incy_desktop is not None:
            vals.update(self.incy_desktop.rust_values())
        return vals


def check_happ_desktop_release(release: HappDesktopRelease) -> None:
    _check_version(release.version)
    if not (_DIGITS_RE.match(release.ua_build_stamp) and _DIGITS_RE.match(release.ua_suffix)):
        raise HappSubFormatError("Happ Desktop User-Agent build stamp and suffix must be decimal digits")


def check_incy_android_release(release: IncyAndroidRelease) -> None:
    _check_version(release.version)
    if not 0 < release.version_code < 2**32:
        raise HappSubFormatError(f"versionCode {release.version_code} does not fit in u32")


def check_incy_desktop_release(release: IncyDesktopRelease) -> None:
    _check_version(release.version)


_check_happ_desktop_release = check_happ_desktop_release
_check_incy_android_release = check_incy_android_release
_check_incy_desktop_release = check_incy_desktop_release


def _check_release(release: Release) -> None:
    _check_version(release.version)
    if not 0 < release.version_code < 2**32:
        raise HappSubFormatError(f"versionCode {release.version_code} does not fit in u32")
    if not (_DIGITS_RE.match(release.ua_build_stamp) and _DIGITS_RE.match(release.ua_suffix)):
        raise HappSubFormatError("User-Agent build stamp and suffix must be decimal digits")
    if release.desktop is not None:
        _check_happ_desktop_release(release.desktop)
    if release.incy is not None:
        _check_incy_android_release(release.incy)
    if release.incy_desktop is not None:
        _check_incy_desktop_release(release.incy_desktop)


def release_from_meta(meta: Mapping[str, Any]) -> Release:
    """Read the release constants `extract --meta` records from the manifest and the UA builder."""
    try:
        release = Release(
            version=str(meta["app_version"]),
            version_code=int(meta["versionCode"]),
            ua_build_stamp=str(meta["ua_build_stamp"]),
            ua_suffix=str(meta["ua_suffix"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise HappSubFormatError(f"meta.json lacks the release constants: {exc}") from exc
    _check_release(release)
    return release


def _try_release_const(source: str, name: str, ty: str) -> re.Match[str] | None:
    matches = list(re.finditer(_RELEASE_CONST_RE.format(name=name, ty=re.escape(ty)), source, re.M))
    if len(matches) > 1:
        raise HappSubFormatError(f"release.rs: expected one `pub const {name}: {ty}`, found {len(matches)}")
    return matches[0] if matches else None


def _release_const(source: str, name: str, ty: str) -> re.Match[str]:
    m = _try_release_const(source, name, ty)
    if m is None:
        raise HappSubFormatError(f"release.rs: expected one `pub const {name}: {ty}`, found 0")
    return m


def parse_release_rs(source: str) -> Release:
    """Parse the release constants from `release.rs` across all supported platforms."""
    values: dict[str, str] = {}
    for name, ty in _RELEASE_FIELDS:
        raw = _release_const(source, name, ty)["value"]
        if ty == "&str":
            m = _STR_VALUE_RE.match(raw)
            if m is None:
                raise HappSubFormatError(f"release.rs: {name} is not a plain string literal")
            values[name] = m["s"]
        else:
            if not _DIGITS_RE.match(raw):
                raise HappSubFormatError(f"release.rs: {name} is not a decimal literal")
            values[name] = raw

    desktop: HappDesktopRelease | None = None
    desktop_m = _try_release_const(source, "HAPP_DESKTOP_VERSION", "&str")
    if desktop_m is not None:
        d_ver_m = _STR_VALUE_RE.match(desktop_m["value"])
        if not d_ver_m:
            raise HappSubFormatError("release.rs: HAPP_DESKTOP_VERSION is not a plain string literal")
        d_stamp_raw = _release_const(source, "HAPP_DESKTOP_UA_BUILD_STAMP", "&str")["value"]
        d_stamp_m = _STR_VALUE_RE.match(d_stamp_raw)
        if not d_stamp_m or not _DIGITS_RE.match(d_stamp_m["s"]):
            raise HappSubFormatError("release.rs: HAPP_DESKTOP_UA_BUILD_STAMP is not a decimal string literal")
        d_suffix_raw = _release_const(source, "HAPP_DESKTOP_UA_SUFFIX", "&str")["value"]
        d_suffix_m = _STR_VALUE_RE.match(d_suffix_raw)
        if not d_suffix_m or not _DIGITS_RE.match(d_suffix_m["s"]):
            raise HappSubFormatError("release.rs: HAPP_DESKTOP_UA_SUFFIX is not a decimal string literal")

        bundle_id = "su.happ.desktop.linux"
        b_id_m = _try_release_const(source, "HAPP_DESKTOP_BUNDLE_ID_LINUX", "&str")
        if b_id_m:
            bm = _STR_VALUE_RE.match(b_id_m["value"])
            if bm:
                bundle_id = bm["s"]

        api_ver = "1.0"
        api_m = _try_release_const(source, "HAPP_API_VERSION", "&str")
        if api_m:
            am = _STR_VALUE_RE.match(api_m["value"])
            if am:
                api_ver = am["s"]

        desktop = HappDesktopRelease(
            version=d_ver_m["s"],
            ua_build_stamp=d_stamp_m["s"],
            ua_suffix=d_suffix_m["s"],
            bundle_id_linux=bundle_id,
            api_version=api_ver,
        )

    incy: IncyAndroidRelease | None = None
    incy_m = _try_release_const(source, "INCY_VERSION", "&str")
    if incy_m is not None:
        i_ver_m = _STR_VALUE_RE.match(incy_m["value"])
        if not i_ver_m:
            raise HappSubFormatError("release.rs: INCY_VERSION is not a plain string literal")
        i_code_raw = _release_const(source, "INCY_VERSION_CODE", "u32")["value"]
        if not _DIGITS_RE.match(i_code_raw):
            raise HappSubFormatError("release.rs: INCY_VERSION_CODE is not a decimal literal")
        incy = IncyAndroidRelease(version=i_ver_m["s"], version_code=int(i_code_raw))

    incy_desktop: IncyDesktopRelease | None = None
    incy_d_m = _try_release_const(source, "INCY_DESKTOP_VERSION", "&str")
    if incy_d_m is not None:
        id_ver_m = _STR_VALUE_RE.match(incy_d_m["value"])
        if not id_ver_m:
            raise HappSubFormatError("release.rs: INCY_DESKTOP_VERSION is not a plain string literal")
        incy_desktop = IncyDesktopRelease(version=id_ver_m["s"])

    return Release(
        version=values["HAPP_VERSION"],
        version_code=int(values["HAPP_VERSION_CODE"]),
        ua_build_stamp=values["HAPP_UA_BUILD_STAMP"],
        ua_suffix=values["HAPP_UA_SUFFIX"],
        desktop=desktop,
        incy=incy,
        incy_desktop=incy_desktop,
    )


def update_release_rs(
    source: str,
    release: Release | HappDesktopRelease | IncyAndroidRelease | IncyDesktopRelease | None = None,
    *,
    desktop: HappDesktopRelease | None = None,
    incy: IncyAndroidRelease | None = None,
    incy_desktop: IncyDesktopRelease | None = None,
) -> str:
    """Rewrite the values of the release constants; comments and layout stay as they are."""
    rust_values: dict[tuple[str, str], str] = {}
    if isinstance(release, Release):
        _check_release(release)
        values = (
            f'"{release.version}"',
            str(release.version_code),
            f'"{release.ua_build_stamp}"',
            f'"{release.ua_suffix}"',
        )
        rust_values.update(dict(zip(_RELEASE_FIELDS, values, strict=True)))
        if release.desktop is not None:
            rust_values.update(release.desktop.rust_values())
        if release.incy is not None:
            rust_values.update(release.incy.rust_values())
        if release.incy_desktop is not None:
            rust_values.update(release.incy_desktop.rust_values())
    elif isinstance(release, HappDesktopRelease):
        _check_happ_desktop_release(release)
        rust_values.update(release.rust_values())
    elif isinstance(release, IncyAndroidRelease):
        _check_incy_android_release(release)
        rust_values.update(release.rust_values())
    elif isinstance(release, IncyDesktopRelease):
        _check_incy_desktop_release(release)
        rust_values.update(release.rust_values())

    if desktop is not None:
        _check_happ_desktop_release(desktop)
        rust_values.update(desktop.rust_values())
    if incy is not None:
        _check_incy_android_release(incy)
        rust_values.update(incy.rust_values())
    if incy_desktop is not None:
        _check_incy_desktop_release(incy_desktop)
        rust_values.update(incy_desktop.rust_values())

    text = source
    for (name, ty), value in rust_values.items():
        m = _release_const(text, name, ty)
        text = text[: m.start("value")] + value + text[m.end("value") :]
    return text


def release_sha256(release: Release | HappDesktopRelease | IncyAndroidRelease | IncyDesktopRelease) -> str:
    if isinstance(release, HappDesktopRelease):
        canonical = f"desktop:{release.version}\n{release.ua_build_stamp}\n{release.ua_suffix}\n"
    elif isinstance(release, IncyAndroidRelease):
        canonical = f"incy:{release.version}\n{release.version_code}\n"
    elif isinstance(release, IncyDesktopRelease):
        canonical = f"incy_desktop:{release.version}\n"
    else:
        canonical = f"{release.version}\n{release.version_code}\n{release.ua_build_stamp}\n{release.ua_suffix}\n"
        if release.desktop is not None:
            canonical += (
                f"desktop:{release.desktop.version}\n{release.desktop.ua_build_stamp}\n{release.desktop.ua_suffix}\n"
            )
        if release.incy is not None:
            canonical += f"incy:{release.incy.version}\n{release.incy.version_code}\n"
        if release.incy_desktop is not None:
            canonical += f"incy_desktop:{release.incy_desktop.version}\n"
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def load_release(repo: Path) -> Release:
    path = repo / RELEASE_RS
    if not path.exists():
        raise HappSubFormatError(f"{RELEASE_RS.as_posix()} not found; happ-sub predates generated release constants")
    return parse_release_rs(path.read_text(encoding="utf-8"))


def device_happ_version(repo: Path) -> str | None:
    return load_release(repo).version if (repo / RELEASE_RS).exists() else None


def _join_words(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


@dataclass(frozen=True)
class SyncPlan:
    drift: bool
    table_sha256: str
    version: str
    matched: str | None = None
    generation: int | None = None
    branch: str | None = None
    title: str | None = None
    changed_ids: tuple[str, ...] = ()
    previous_generation: int | None = None
    keys_drift: bool = False
    signers_drift: bool = False
    signers_sha256: str | None = None
    signers: Signers | None = None
    previous_signers: Signers | None = None
    device_happ_version: str | None = None
    release_drift: bool = False
    release_sha256: str | None = None
    release: Release | None = None
    previous_release: Release | None = None
    release_unknown: bool = False

    @property
    def sync_sha256(self) -> str:
        """Digest of everything a sync PR carries; later runs find an open PR by it."""
        parts = [self.table_sha256]
        if self.signers_sha256 is not None:
            parts.append(self.signers_sha256)
        if self.release_sha256 is not None:
            parts.append(f"release:{self.release_sha256}")
        if len(parts) == 1:
            return self.table_sha256
        combined = "".join(f"{p}\n" for p in parts)
        return hashlib.sha256(combined.encode("ascii")).hexdigest()

    @property
    def rewrite_signers(self) -> bool:
        """signers.rs is regenerated on a new certificate, and on a new release to follow its version."""
        if self.signers is None or self.previous_signers is None:
            return False
        return self.signers_drift or (
            self.release_drift and self.previous_signers.apk_version != self.signers.apk_version
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "drift": self.drift,
            "keys_drift": self.keys_drift,
            "signers_drift": self.signers_drift,
            "release_drift": self.release_drift,
            "release_unknown": self.release_unknown,
            "table_sha256": self.table_sha256,
            "signers_sha256": self.signers_sha256,
            "release_sha256": self.release_sha256,
            "sync_sha256": self.sync_sha256,
            "version": self.version,
            "matched": self.matched,
            "generation": self.generation,
            "branch": self.branch,
            "title": self.title,
            "changed_ids": list(self.changed_ids),
            "previous_generation": self.previous_generation,
        }


def _merge_release(release: Release | None, previous: Release | None) -> Release | None:
    if release is None:
        return None
    if previous is None:
        return release
    return Release(
        version=release.version,
        version_code=release.version_code,
        ua_build_stamp=release.ua_build_stamp,
        ua_suffix=release.ua_suffix,
        desktop=release.desktop if release.desktop is not None else previous.desktop,
        incy=release.incy if release.incy is not None else previous.incy,
        incy_desktop=release.incy_desktop if release.incy_desktop is not None else previous.incy_desktop,
    )


def plan_sync(
    repo: Path,
    entries: KeyTableEntries,
    version: str,
    signers: Signers | None = None,
    release: Release | None = None,
    release_unknown: bool = False,
    desktop: HappDesktopRelease | None = None,
    incy: IncyAndroidRelease | None = None,
    incy_desktop: IncyDesktopRelease | None = None,
) -> SyncPlan:
    """Compare an extracted table, and if given the signer set and release constants, with happ-sub."""
    tables = load_tables(repo)
    digest = table_sha256(entries)
    match = find_matching_table(entries, tables)

    previous_signers = load_signers(repo) if signers is not None else None
    signers_drift = (
        signers is not None
        and previous_signers is not None
        and (signers.scheme, signers.certs) != (previous_signers.scheme, previous_signers.certs)
    )
    previous_release = (
        load_release(repo)
        if (release is not None or desktop is not None or incy is not None or incy_desktop is not None)
        else None
    )
    if release is not None:
        release = _merge_release(release, previous_release)
        assert release is not None
        if desktop is not None:
            release = replace(release, desktop=desktop)
        if incy is not None:
            release = replace(release, incy=incy)
        if incy_desktop is not None:
            release = replace(release, incy_desktop=incy_desktop)
    elif previous_release is not None and (desktop is not None or incy is not None or incy_desktop is not None):
        release = Release(
            version=previous_release.version,
            version_code=previous_release.version_code,
            ua_build_stamp=previous_release.ua_build_stamp,
            ua_suffix=previous_release.ua_suffix,
            desktop=desktop if desktop is not None else previous_release.desktop,
            incy=incy if incy is not None else previous_release.incy,
            incy_desktop=incy_desktop if incy_desktop is not None else previous_release.incy_desktop,
        )

    release_drift = release is not None and release != previous_release
    fields: dict[str, Any] = {
        "signers_drift": signers_drift,
        "signers_sha256": signers_sha256(signers) if signers is not None else None,
        "signers": signers,
        "previous_signers": previous_signers,
        # Only a release left unsynced can leave HAPP_VERSION behind the new signers.
        "device_happ_version": device_happ_version(repo) if signers_drift and release is None else None,
        "release_drift": release_drift,
        "release_sha256": release_sha256(release) if release is not None else None,
        "release": release,
        "previous_release": previous_release,
        "release_unknown": release_unknown,
    }

    generation: int | None = None
    items: list[str] = []
    if match is None:
        newest = tables[-1]
        generation = newest.generation + 1
        previous = newest.as_dict()
        fields |= {
            "matched": None,
            "generation": generation,
            "changed_ids": tuple(kid for kid, key in entries if previous.get(kid) != key),
            "previous_generation": newest.generation,
            "keys_drift": True,
        }
        items.append(f"generation {generation} body keys")
    else:
        fields["matched"] = f"gen{match.generation}"
    if signers_drift:
        items.append("the signing certificate")
    if release_drift:
        items.append("the release constants")

    if not items:
        return SyncPlan(drift=False, table_sha256=digest, version=version, **fields)
    if generation is not None:
        branch, title = f"keys/gen{generation}-{version}", f"feat(keys): add {_join_words(items)} from Happ {version}"
    else:
        kind = "signers" if signers_drift else "release"
        branch, title = f"{kind}/{version}", f"feat(device): update {_join_words(items)} from Happ {version}"
    return SyncPlan(drift=True, table_sha256=digest, version=version, branch=branch, title=title, **fields)


def apply_sync(repo: Path, plan: SyncPlan, entries: KeyTableEntries) -> list[Path]:
    """Write the files a drift calls for. Returns them; nothing is written if any edit fails."""
    writes: list[tuple[Path, str]] = []
    if plan.keys_drift and plan.generation is not None:
        keys_dir = repo / KEYS_DIR
        gen_path = keys_dir / f"gen{plan.generation}.rs"
        if gen_path.exists():
            raise HappSubFormatError(f"{gen_path} already exists")
        mod_path = keys_dir / "mod.rs"
        mod_rs = register_table(mod_path.read_text(encoding="utf-8"), plan.generation, plan.version)
        writes += [(gen_path, render_gen_rs(plan.generation, plan.version, entries)), (mod_path, mod_rs)]
    if plan.rewrite_signers and plan.signers is not None:
        writes.append((repo / DEVICE_DIR / "signers.rs", render_signers_rs(plan.signers)))
    if plan.signers_drift and plan.signers is not None:
        device_mod = repo / DEVICE_DIR / "mod.rs"
        writes.append((device_mod, update_device_pins(device_mod.read_text(encoding="utf-8"), plan.signers)))
    if plan.release_drift and plan.release is not None:
        release_path = repo / RELEASE_RS
        writes.append((release_path, update_release_rs(release_path.read_text(encoding="utf-8"), plan.release)))
    for path, text in writes:
        path.write_text(text, encoding="utf-8")
    return [path for path, _ in writes]


SYNC_MARKER = "happ-sub-sync-sha256"
SIGNERS_SECTION = "Signing certificate changed: SSAID values computed by clients change for new installs"
RELEASE_SECTION = "Happ version updated"
RELEASE_UNKNOWN_SECTION = "Happ version not updated: User-Agent builder not found"


def _describe_signers(signers: Signers) -> str:
    _, scheme_name = SIG_SCHEMES[signers.scheme]
    digests = ", ".join(f"`{d}`" for d in signers.sha256())
    return f"{scheme_name}, SHA-256 {digests} (Happ {signers.apk_version})"


def _signers_section(plan: SyncPlan) -> list[str]:
    assert plan.signers is not None
    assert plan.previous_signers is not None
    lines = [
        f"## {SIGNERS_SECTION}",
        "",
        f"- Before: {_describe_signers(plan.previous_signers)}",
        f"- After: {_describe_signers(plan.signers)}",
        "",
        "`src/device/signers.rs` is regenerated, and the certificate-derived pins in `src/device/mod.rs` "
        "(`signers_digest_pinned`, `ssaid_matches_vector`) are recomputed. A Happ install that already exists "
        "keeps the SSAID Android stored for its uid, so the stored value no longer equals the computed one "
        "for those devices.",
    ]
    if plan.device_happ_version is not None and plan.device_happ_version != plan.signers.apk_version:
        lines += [
            "",
            f"`HAPP_VERSION` is still {plan.device_happ_version}. `signers_digest_pinned` fails until the "
            f"release constants describe Happ {plan.signers.apk_version}.",
        ]
    return lines


def _describe_release(release: Release, other: Release | None = None) -> str:
    parts = [
        f"Happ {release.version}, versionCode {release.version_code}, "
        + f"User-Agent build stamp `{release.ua_build_stamp}`, suffix `{release.ua_suffix}`"
    ]
    if release.desktop is not None and (other is None or release.desktop != other.desktop):
        parts.append(
            f"Happ Desktop {release.desktop.version}, User-Agent build stamp `{release.desktop.ua_build_stamp}`, "
            + f"suffix `{release.desktop.ua_suffix}`"
        )
    if release.incy is not None and (other is None or release.incy != other.incy):
        parts.append(f"Incy {release.incy.version}, versionCode {release.incy.version_code}")
    if release.incy_desktop is not None and (other is None or release.incy_desktop != other.incy_desktop):
        parts.append(f"Incy Desktop {release.incy_desktop.version}")
    return "; ".join(parts)


def _release_section(plan: SyncPlan) -> list[str]:
    assert plan.release is not None
    assert plan.previous_release is not None
    text = (
        f"`{RELEASE_RS.as_posix()}` is regenerated, so the User-Agent happ-sub sends identifies as "
        f"Happ {plan.release.version}."
    )
    if plan.rewrite_signers and not plan.signers_drift:
        text += " `HAPP_SIGNERS.apk_version` follows; the certificates are unchanged."
    return [
        f"## {RELEASE_SECTION}",
        "",
        f"- Before: {_describe_release(plan.previous_release, plan.release)}",
        f"- After: {_describe_release(plan.release, plan.previous_release)}",
        "",
        text,
    ]


def _release_unknown_section() -> list[str]:
    return [
        f"## {RELEASE_UNKNOWN_SECTION}",
        "",
        "The User-Agent builder was not found in this APK (see the `user_agent_builder` check), so "
        f"`{RELEASE_RS.as_posix()}` is left unchanged. Bumping only `HAPP_VERSION` and `HAPP_VERSION_CODE` "
        "would pair them with the old build stamp and suffix, a User-Agent no Happ release sends.",
    ]


def build_pr_body(plan: SyncPlan, meta: Mapping[str, Any], report: Mapping[str, Any], run_url: str | None) -> str:
    lines: list[str] = []
    if plan.keys_drift:
        assert plan.generation is not None
        lines.append(
            f"Happ {plan.version} ships a body key table that matches none of the tables in `src/keys/`. "
            f"This adds it as generation {plan.generation} (`{table_id(plan.generation, plan.version)}`) "
            "and puts it first in `ALL_TABLES`. `DEFAULT_TABLE` is unchanged."
        )
    elif plan.signers_drift:
        lines.append(
            f"Happ {plan.version} is signed with a certificate set that differs from `HAPP_SIGNERS`. "
            f"Its body key table equals {plan.matched}."
        )
    elif plan.release_drift:
        lines.append(
            f"Happ {plan.version} is out. Its body key table equals {plan.matched} and its signing certificate is "
            "unchanged, so only the release constants move."
        )
    lines.append("")
    if plan.signers_drift:
        lines += [*_signers_section(plan), ""]
    if plan.release_drift:
        lines += [*_release_section(plan), ""]
    if plan.release_unknown:
        lines += [*_release_unknown_section(), ""]
    lines += [
        f"- APK version: {meta.get('app_version')} (versionCode {meta.get('versionCode')})",
        f"- APK SHA-256: `{meta.get('apk_sha256')}`",
        f"- Signing certificate SHA-1 (base64): `{meta.get('expected_certificate_digest')}`",
    ]
    if plan.keys_drift:
        lines.append(f"- Keys that differ from gen{plan.previous_generation}: {len(plan.changed_ids)} of 90")
    if run_url:
        lines.append(f"- Workflow run: {run_url}")
    lines += ["", "| Check | Result |", "| --- | --- |"]
    for name, check in sorted(report.get("checks", {}).items()):
        if check.get("passed"):
            result = "passed"
        elif check.get("is_warning"):
            result = f"warning: {check.get('error')}"
        else:
            result = f"failed: {check.get('error')}"
        lines.append(f"| `{name}` | {result} |")
    lines += [
        "",
        f"Overall: {'all critical checks passed' if report.get('all_passed') else 'CRITICAL CHECKS FAILED'}, "
        f"{report.get('warnings_count', 0)} warning(s).",
        "",
        f"<!-- {SYNC_MARKER}: {plan.sync_sha256} -->",
    ]
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class ReleaseSyncPlan:
    drift: bool
    branch: str | None = None
    title: str | None = None
    sync_sha256: str | None = None
    release: Release | None = None
    previous_release: Release | None = None
    happ_drift: bool = False
    desktop_drift: bool = False
    incy_drift: bool = False
    incy_desktop_drift: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "drift": self.drift,
            "branch": self.branch,
            "title": self.title,
            "sync_sha256": self.sync_sha256,
            "happ_drift": self.happ_drift,
            "desktop_drift": self.desktop_drift,
            "incy_drift": self.incy_drift,
            "incy_desktop_drift": self.incy_desktop_drift,
            "release": {
                "version": self.release.version if self.release else None,
                "desktop_version": self.release.desktop.version if self.release and self.release.desktop else None,
                "incy_version": self.release.incy.version if self.release and self.release.incy else None,
                "incy_desktop_version": self.release.incy_desktop.version
                if self.release and self.release.incy_desktop
                else None,
            }
            if self.release
            else None,
        }


def plan_release_sync(
    repo: Path,
    *,
    happ: Release | None = None,
    desktop: HappDesktopRelease | None = None,
    incy: IncyAndroidRelease | None = None,
    incy_desktop: IncyDesktopRelease | None = None,
) -> ReleaseSyncPlan:
    """Compare desired platform release versions against a happ-sub checkout's release.rs."""
    previous = load_release(repo)
    target = Release(
        version=happ.version if happ is not None else previous.version,
        version_code=happ.version_code if happ is not None else previous.version_code,
        ua_build_stamp=happ.ua_build_stamp if happ is not None else previous.ua_build_stamp,
        ua_suffix=happ.ua_suffix if happ is not None else previous.ua_suffix,
        desktop=desktop if desktop is not None else previous.desktop,
        incy=incy if incy is not None else previous.incy,
        incy_desktop=incy_desktop if incy_desktop is not None else previous.incy_desktop,
    )
    _check_release(target)

    happ_drift = happ is not None and (happ.version, happ.version_code, happ.ua_build_stamp, happ.ua_suffix) != (
        previous.version,
        previous.version_code,
        previous.ua_build_stamp,
        previous.ua_suffix,
    )
    desktop_drift = desktop is not None and desktop != previous.desktop
    incy_drift = incy is not None and incy != previous.incy
    incy_desktop_drift = incy_desktop is not None and incy_desktop != previous.incy_desktop

    drift = happ_drift or desktop_drift or incy_drift or incy_desktop_drift
    if not drift:
        return ReleaseSyncPlan(drift=False, release=target, previous_release=previous)

    # Pick branch and title
    if happ_drift and not (desktop_drift or incy_drift or incy_desktop_drift):
        branch = f"release/{target.version}"
        title = f"feat(release): bump Happ to {target.version}"
    elif desktop_drift and not (happ_drift or incy_drift or incy_desktop_drift):
        assert target.desktop is not None
        branch = f"release/happ-desktop-{target.desktop.version}"
        title = f"feat(release): bump Happ Desktop to {target.desktop.version}"
    elif incy_drift and not (happ_drift or desktop_drift or incy_desktop_drift):
        assert target.incy is not None
        branch = f"release/incy-{target.incy.version}"
        title = f"feat(release): bump Incy to {target.incy.version}"
    elif incy_desktop_drift and not (happ_drift or desktop_drift or incy_drift):
        assert target.incy_desktop is not None
        branch = f"release/incy-desktop-{target.incy_desktop.version}"
        title = f"feat(release): bump Incy Desktop to {target.incy_desktop.version}"
    else:
        targets: list[str] = []
        if happ_drift:
            targets.append(f"Happ {target.version}")
        if desktop_drift and target.desktop:
            targets.append(f"Happ Desktop {target.desktop.version}")
        if incy_drift and target.incy:
            targets.append(f"Incy {target.incy.version}")
        if incy_desktop_drift and target.incy_desktop:
            targets.append(f"Incy Desktop {target.incy_desktop.version}")
        title = f"feat(release): bump {_join_words(targets)}"
        branch = f"release/platforms-{hashlib.sha256(title.encode()).hexdigest()[:8]}"

    sync_sha = release_sha256(target)
    return ReleaseSyncPlan(
        drift=True,
        branch=branch,
        title=title,
        sync_sha256=sync_sha,
        release=target,
        previous_release=previous,
        happ_drift=happ_drift,
        desktop_drift=desktop_drift,
        incy_drift=incy_drift,
        incy_desktop_drift=incy_desktop_drift,
    )


def apply_release_sync(repo: Path, plan: ReleaseSyncPlan) -> list[Path]:
    if not plan.drift or plan.release is None:
        return []
    release_path = repo / RELEASE_RS
    updated = update_release_rs(release_path.read_text(encoding="utf-8"), plan.release)
    _ = release_path.write_text(updated, encoding="utf-8")
    return [release_path]


def build_release_pr_body(plan: ReleaseSyncPlan, run_url: str | None = None) -> str:
    assert plan.release is not None
    assert plan.previous_release is not None
    lines = [
        "## Release constants updated",
        "",
    ]
    if plan.happ_drift:
        lines += [
            f"- **Happ Android**: bumped from {plan.previous_release.version} "
            + f"({plan.previous_release.version_code}) to {plan.release.version} ({plan.release.version_code})",
            f"  - Build stamp: `{plan.release.ua_build_stamp}` (was `{plan.previous_release.ua_build_stamp}`)",
            f"  - Suffix: `{plan.release.ua_suffix}` (was `{plan.previous_release.ua_suffix}`)",
        ]
    if plan.desktop_drift and plan.release.desktop:
        prev_d = plan.previous_release.desktop
        prev_desc = (
            f"{prev_d.version} (stamp `{prev_d.ua_build_stamp}`, suffix `{prev_d.ua_suffix}`)" if prev_d else "none"
        )
        lines += [
            f"- **Happ Desktop**: bumped from {prev_desc} to {plan.release.desktop.version} "
            + f"(stamp `{plan.release.desktop.ua_build_stamp}`, suffix `{plan.release.desktop.ua_suffix}`)"
        ]
    if plan.incy_drift and plan.release.incy:
        prev_i = plan.previous_release.incy
        prev_desc = f"{prev_i.version} ({prev_i.version_code})" if prev_i else "none"
        lines += [
            f"- **Incy Android**: bumped from {prev_desc} to {plan.release.incy.version} "
            + f"({plan.release.incy.version_code})"
        ]
    if plan.incy_desktop_drift and plan.release.incy_desktop:
        prev_id = plan.previous_release.incy_desktop
        prev_desc = prev_id.version if prev_id else "none"
        lines += [f"- **Incy Desktop**: bumped from {prev_desc} to {plan.release.incy_desktop.version}"]
    lines += [
        "",
        f"`{RELEASE_RS.as_posix()}` was updated in place.",
    ]
    if run_url:
        lines += ["", f"- Run: {run_url}"]
    if plan.sync_sha256:
        lines += ["", f"<!-- {SYNC_MARKER}: {plan.sync_sha256} -->"]
    return "\n".join(lines) + "\n"
