"""Tests for Unicorn ARM64 native dumper."""

from pathlib import Path

from androguard.core.apk import APK

from happ_keys.native import UnicornNativeDumper


def escape_c_string(raw: bytes) -> str:
    """Format string identically to dump_native.c escaping."""
    out: list[str] = []
    for b in raw:
        if b == ord("\n"):
            out.append("\\n")
        elif b == ord("\r"):
            out.append("\\r")
        elif b == ord("\t"):
            out.append("\\t")
        elif b == ord("\\"):
            out.append("\\\\")
        elif b < 0x20 or b == 0x7F:
            out.append(f"\\x{b:02x}")
        else:
            out.append(chr(b))
    return "".join(out)


def test_unicorn_raw_dump_matches_reference(apk_path: Path, ref_keys_raw: Path) -> None:
    """Compare Unicorn dump of error codes 0..1100 against emulator reference output."""
    apk = APK(str(apk_path))
    so_bytes = apk.get_file("lib/arm64-v8a/liberror-code.so")
    assert so_bytes is not None

    dumper = UnicornNativeDumper(so_bytes)

    # Read reference dump
    ref_dict: dict[int, str] = {}
    for line in ref_keys_raw.read_text(encoding="utf-8").strip().splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2:
            ref_dict[int(parts[0])] = parts[1]

    assert len(ref_dict) == 1101

    mismatches: list[tuple[int, str, str]] = []
    for code in range(1101):
        s = dumper.get_string(code)
        escaped_s = escape_c_string(s.encode("utf-8"))
        ref_s = ref_dict.get(code, "")
        if escaped_s != ref_s:
            mismatches.append((code, escaped_s, ref_s))

    assert len(mismatches) == 0, f"Found {len(mismatches)} mismatches in raw dump: {mismatches[:5]}"
