"""Read and extend the body key tables of the happ-sub Rust crate.

happ-sub keeps each key generation in `src/keys/gen<N>.rs` as a `KEYS_GEN<N>` slice of
`(&str, &[u8; 16])` pairs and registers it in `src/keys/mod.rs` as a `KeyTable` const listed
in `ALL_TABLES`, newest first. Body keys carry no version on the wire, so a table extracted
from a new APK either equals an existing generation or becomes the next one.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

KEYS_DIR = Path("src") / "keys"

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "drift": self.drift,
            "table_sha256": self.table_sha256,
            "version": self.version,
            "matched": self.matched,
            "generation": self.generation,
            "branch": self.branch,
            "title": self.title,
            "changed_ids": list(self.changed_ids),
            "previous_generation": self.previous_generation,
        }


def plan_sync(repo: Path, entries: KeyTableEntries, version: str) -> SyncPlan:
    tables = load_tables(repo)
    digest = table_sha256(entries)
    match = find_matching_table(entries, tables)
    if match is not None:
        return SyncPlan(drift=False, table_sha256=digest, version=version, matched=f"gen{match.generation}")

    newest = tables[-1]
    generation = newest.generation + 1
    previous = newest.as_dict()
    changed = tuple(kid for kid, key in entries if previous.get(kid) != key)
    return SyncPlan(
        drift=True,
        table_sha256=digest,
        version=version,
        generation=generation,
        branch=f"keys/gen{generation}-{version}",
        title=f"feat(keys): add generation {generation} body keys from Happ {version}",
        changed_ids=changed,
        previous_generation=newest.generation,
    )


def apply_sync(repo: Path, plan: SyncPlan, entries: KeyTableEntries) -> list[Path]:
    """Write `gen<N>.rs` and register it in mod.rs. Returns the files written."""
    if not plan.drift or plan.generation is None:
        return []
    keys_dir = repo / KEYS_DIR
    gen_path = keys_dir / f"gen{plan.generation}.rs"
    if gen_path.exists():
        raise HappSubFormatError(f"{gen_path} already exists")
    mod_path = keys_dir / "mod.rs"
    mod_rs = register_table(mod_path.read_text(encoding="utf-8"), plan.generation, plan.version)
    gen_path.write_text(render_gen_rs(plan.generation, plan.version, entries), encoding="utf-8")
    mod_path.write_text(mod_rs, encoding="utf-8")
    return [gen_path, mod_path]


TABLE_MARKER = "happ-keys-table-sha256"


def build_pr_body(plan: SyncPlan, meta: Mapping[str, Any], report: Mapping[str, Any], run_url: str | None) -> str:
    assert plan.generation is not None
    lines = [
        f"Happ {plan.version} ships a body key table that matches none of the tables in `src/keys/`. "
        f"This adds it as generation {plan.generation} (`{table_id(plan.generation, plan.version)}`) "
        "and puts it first in `ALL_TABLES`. `DEFAULT_TABLE` is unchanged.",
        "",
        f"- APK version: {meta.get('app_version')} (versionCode {meta.get('versionCode')})",
        f"- APK SHA-256: `{meta.get('apk_sha256')}`",
        f"- Signing certificate SHA-1 (base64): `{meta.get('expected_certificate_digest')}`",
        f"- Keys that differ from gen{plan.previous_generation}: {len(plan.changed_ids)} of 90",
    ]
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
        f"<!-- {TABLE_MARKER}: {plan.table_sha256} -->",
    ]
    return "\n".join(lines) + "\n"
