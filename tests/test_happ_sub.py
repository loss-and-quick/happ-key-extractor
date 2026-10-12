"""happ-sub key table and signer parsers and generators, checked against snapshots of happ-sub's sources."""

import base64
import hashlib
import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from happ_keys import happ_sub
from happ_keys.cli import main

DATA_DIR = Path(__file__).parent / "data"
SNAPSHOT_DIR = DATA_DIR / "happ-sub"
GEN1_RS = (SNAPSHOT_DIR / "src" / "keys" / "gen1.rs").read_text(encoding="utf-8")
MOD_RS = (SNAPSHOT_DIR / "src" / "keys" / "mod.rs").read_text(encoding="utf-8")
SIGNERS_RS = (SNAPSHOT_DIR / "src" / "device" / "signers.rs").read_text(encoding="utf-8")
DEVICE_MOD_RS = (SNAPSHOT_DIR / "src" / "device" / "mod.rs").read_text(encoding="utf-8")
HAPP_CERT_SHA256 = "397e98abed03c5f263ffaf4e8a1043b2a59f538b99e75cf152fa05a7e8007d8d"
# Not a certificate: happ-sub treats signer certificates as opaque bytes.
FAKE_CERT = bytes((i * 37 + 11) % 256 for i in range(700))


def _reference_keys() -> dict[str, str]:
    return json.loads((DATA_DIR / "keys.json").read_text(encoding="utf-8"))


def _rotated_keys() -> dict[str, str]:
    return {kid: f"{kid}:{(i * 7919):010d}"[:16] for i, kid in enumerate(sorted(_reference_keys()))}


def test_gen1_parses_to_reference_table() -> None:
    table = happ_sub.parse_key_table(GEN1_RS)

    assert table.generation == 1
    assert len(table.entries) == 90
    assert table.entries == happ_sub.table_from_keys_json(_reference_keys())


def test_gen1_round_trips_byte_exact() -> None:
    table = happ_sub.parse_key_table(GEN1_RS)
    assert happ_sub.render_gen_rs(1, "4.3.0..4.7.1", table.entries) == GEN1_RS


def test_render_fake_table_exact_text() -> None:
    entries = (
        ("key01", b"key01:a\"b\\c'd0xy"),
        ("key02", b"key02:\x00\x7f\xff abcdef"),
    )
    expected = (
        "/// 2 AES-128 keys for Generation 7 (4.9.0).\n"
        "pub const KEYS_GEN7: &[(&str, &[u8; 16])] = &[\n"
        '    ("key01", b"key01:a\\"b\\\\c\'d0xy"),\n'
        '    ("key02", b"key02:\\x00\\x7f\\xff abcdef"),\n'
        "];\n"
    )
    rendered = happ_sub.render_gen_rs(7, "4.9.0", entries)

    assert rendered == expected
    assert happ_sub.parse_key_table(rendered).entries == entries


def test_escape_round_trips_every_byte() -> None:
    data = bytes(range(256))
    assert happ_sub.unescape_byte_string(happ_sub.escape_byte_string(data)) == data


def test_parser_accepts_rustfmt_variations() -> None:
    source = (
        "// generated\n"
        "pub const KEYS_GEN4: &[(&str, &[u8; 16])] = &[\n"
        "    // first\n"
        '    ( "key01" , b"key01:\\x41\\n\\t\\0\\\'\\r\\\n         wxyz" ),\n'
        '    ("key02", b"key02:]; trickyx")\n'
        "];\n"
    )
    table = happ_sub.parse_key_table(source)

    assert table.generation == 4
    assert table.entries == (("key01", b"key01:A\n\t\0'\rwxyz"), ("key02", b"key02:]; trickyx"))


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("pub const OTHER: u8 = 1;", "expected one KEYS_GEN"),
        ('pub const KEYS_GEN1: &[(&str, &[u8; 16])] = &[\n    ("key01", b"short"),\n];', "expected 16"),
        ("pub const KEYS_GEN1: &[(&str, &[u8; 16])] = &[\n    KEY,\n];", "unexpected token"),
    ],
)
def test_parser_rejects_unexpected_input(source: str, message: str) -> None:
    with pytest.raises(happ_sub.HappSubFormatError, match=message):
        happ_sub.parse_key_table(source)


def test_register_table_exact_text() -> None:
    expected = (
        MOD_RS.replace("mod gen1;\n", "mod gen1;\nmod gen2;\n")
        .replace("pub use gen1::KEYS_GEN1;\n", "pub use gen1::KEYS_GEN1;\npub use gen2::KEYS_GEN2;\n")
        .replace(
            "    entries: KEYS_GEN1,\n};\n",
            "    entries: KEYS_GEN1,\n};\n"
            "\n"
            "/// Key table for Generation 2 (measured in Happ 4.8.0).\n"
            "pub const TABLE_GEN2_4_8_0: KeyTable = KeyTable {\n"
            '    id: "gen2-4.8.0",\n'
            "    entries: KEYS_GEN2,\n"
            "};\n",
        )
        .replace(
            "pub const ALL_TABLES: &[&KeyTable] = &[&TABLE_GEN1_4_3_0_TO_4_7_1];",
            "pub const ALL_TABLES: &[&KeyTable] = &[&TABLE_GEN2_4_8_0, &TABLE_GEN1_4_3_0_TO_4_7_1];",
        )
    )
    assert expected != MOD_RS
    assert happ_sub.register_table(MOD_RS, 2, "4.8.0") == expected


def test_register_table_wraps_long_table_list_like_rustfmt() -> None:
    mod_rs = happ_sub.register_table(happ_sub.register_table(MOD_RS, 2, "4.8.0"), 3, "4.10.2")

    assert (
        "pub const ALL_TABLES: &[&KeyTable] = &[\n"
        "    &TABLE_GEN3_4_10_2,\n"
        "    &TABLE_GEN2_4_8_0,\n"
        "    &TABLE_GEN1_4_3_0_TO_4_7_1,\n"
        "];\n"
    ) in mod_rs
    with pytest.raises(happ_sub.HappSubFormatError, match="already declares gen3"):
        happ_sub.register_table(mod_rs, 3, "4.10.3")


def test_register_table_rejects_unsafe_version() -> None:
    with pytest.raises(happ_sub.HappSubFormatError, match="refusing"):
        happ_sub.register_table(MOD_RS, 2, "4.8.0; rm -rf /")


def test_signers_roundtrip() -> None:
    signers = happ_sub.parse_signers_rs(SIGNERS_RS)

    assert signers.scheme == "v2"
    assert signers.apk_version == "4.7.1"
    assert signers.sha256() == [HAPP_CERT_SHA256]
    assert happ_sub.render_signers_rs(signers) == SIGNERS_RS
    # The pins in happ-sub's tests are already those of this signer set.
    assert happ_sub.update_device_pins(DEVICE_MOD_RS, signers) == DEVICE_MOD_RS


def test_ssaid_matches_happ_sub_vectors() -> None:
    # happ-sub's vectors were computed with `openssl dgst -sha256 -mac HMAC`.
    certs = happ_sub.parse_signers_rs(SIGNERS_RS).certs
    assert happ_sub.ssaid(bytes(range(32)), certs) == "013b86e99e8dce53"
    assert happ_sub.ssaid(bytes(range(16)), certs) == "fe3093ae240d87fd"


def test_render_signers_exact_text() -> None:
    signers = happ_sub.Signers(scheme="v3.1", certs=(bytes(range(18)), b"\xff"), apk_version="4.9.0")
    expected = (
        "//! Generated by happ-key-extractor from the Happ release APK. Do not edit by hand.\n"
        "\n"
        "use super::{SigScheme, SignerSet};\n"
        "\n"
        "/// Signers of Happ 4.9.0: APK Signature Scheme v3.1 only, two certificates.\n"
        "pub const HAPP_SIGNERS: SignerSet = SignerSet {\n"
        "    scheme: SigScheme::V31,\n"
        "    certs: &[&CERT_0, &CERT_1],\n"
        '    apk_version: "4.9.0",\n'
        "};\n"
        "\n"
        f"/// DER, SHA-256 {hashlib.sha256(bytes(range(18))).hexdigest()}.\n"
        "#[rustfmt::skip]\n"
        "const CERT_0: [u8; 18] = [\n"
        "    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,\n"
        "    0x10, 0x11,\n"
        "];\n"
        "\n"
        f"/// DER, SHA-256 {hashlib.sha256(bytes([0xFF])).hexdigest()}.\n"
        "#[rustfmt::skip]\n"
        "const CERT_1: [u8; 1] = [\n"
        "    0xff,\n"
        "];\n"
    )
    rendered = happ_sub.render_signers_rs(signers)

    assert rendered == expected
    assert happ_sub.parse_signers_rs(rendered) == signers


def test_render_signers_wraps_long_cert_list_like_rustfmt() -> None:
    signers = happ_sub.Signers(scheme="v1", certs=tuple(bytes([i]) for i in range(12)), apk_version="4.9.0")
    rendered = happ_sub.render_signers_rs(signers)

    assert (
        "    certs: &[\n"
        "        &CERT_0, &CERT_1, &CERT_2, &CERT_3, &CERT_4, &CERT_5, &CERT_6, &CERT_7, &CERT_8, &CERT_9,\n"
        "        &CERT_10, &CERT_11,\n"
        "    ],\n"
    ) in rendered
    assert happ_sub.parse_signers_rs(rendered) == signers


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda s: s.replace("&[&CERT_0]", "&[&CERT_1]"), "undefined &CERT_1"),
        (lambda s: s.replace("[u8; 782]", "[u8; 781]"), "declared 781"),
        (lambda s: s.replace("0x96,\n];", "0x97,\n];"), "documented SHA-256"),
        (lambda s: s.replace("SigScheme::V2", "SigScheme::V4"), "unknown SigScheme::V4"),
        (lambda s: s.replace("0x96,\n];", "CONST,\n];"), "unexpected array element"),
        (lambda s: s.replace("pub const HAPP_SIGNERS", "pub const SIGNERS"), "cannot find `HAPP_SIGNERS`"),
    ],
)
def test_signers_parser_rejects_unexpected_input(edit: Callable[[str], str], message: str) -> None:
    with pytest.raises(happ_sub.HappSubFormatError, match=message):
        happ_sub.parse_signers_rs(edit(SIGNERS_RS))


def _signers_json(certs: list[bytes], scheme: str = "v2", version: str = "4.7.1") -> dict[str, object]:
    return {
        "scheme": scheme,
        "apk_version": version,
        "certs": [base64.b64encode(c).decode("ascii") for c in certs],
        "sha256": [hashlib.sha256(c).hexdigest() for c in certs],
    }


def test_signers_from_json_validates() -> None:
    signers = happ_sub.signers_from_json(_signers_json([FAKE_CERT]))
    assert signers == happ_sub.Signers(scheme="v2", certs=(FAKE_CERT,), apk_version="4.7.1")

    bad_digest = _signers_json([FAKE_CERT]) | {"sha256": [HAPP_CERT_SHA256]}
    for doc, message in [
        (bad_digest, "does not match"),
        (_signers_json([FAKE_CERT], scheme="v4"), "unknown signature scheme"),
        (_signers_json([]), "no certificate"),
        (_signers_json([FAKE_CERT], version="4.8.0; rm"), "refusing"),
    ]:
        with pytest.raises(happ_sub.HappSubFormatError, match=message):
            happ_sub.signers_from_json(doc)


def test_update_device_pins_rewrites_cert_derived_values() -> None:
    signers = happ_sub.Signers(scheme="v3", certs=(FAKE_CERT,), apk_version="4.7.1")
    mod_rs = happ_sub.update_device_pins(DEVICE_MOD_RS, signers)

    expected = (
        DEVICE_MOD_RS.replace("SigScheme::V2);", "SigScheme::V3);")
        .replace("assert_eq!(cert.len(), 782);", "assert_eq!(cert.len(), 700);")
        .replace(HAPP_CERT_SHA256, hashlib.sha256(FAKE_CERT).hexdigest())
        .replace('"013b86e99e8dce53"', f'"{happ_sub.ssaid(bytes(range(32)), [FAKE_CERT])}"')
        .replace('"fe3093ae240d87fd"', f'"{happ_sub.ssaid(bytes(range(16)), [FAKE_CERT])}"')
    )
    assert expected != DEVICE_MOD_RS
    assert mod_rs == expected
    with pytest.raises(happ_sub.HappSubFormatError, match="SHA-256 pin"):
        happ_sub.update_device_pins(DEVICE_MOD_RS.replace(f'"{HAPP_CERT_SHA256}"', "DIGEST"), signers)


@pytest.fixture
def happ_sub_repo(tmp_path: Path) -> Path:
    return Path(shutil.copytree(SNAPSHOT_DIR, tmp_path / "happ-sub"))


def test_reference_table_is_not_drift(happ_sub_repo: Path) -> None:
    plan = happ_sub.plan_sync(happ_sub_repo, happ_sub.table_from_keys_json(_reference_keys()), "4.7.1")

    assert plan.drift is False
    assert plan.matched == "gen1"
    assert happ_sub.apply_sync(happ_sub_repo, plan, ()) == []


def test_drift_generates_next_generation_once(happ_sub_repo: Path) -> None:
    entries = happ_sub.table_from_keys_json(_rotated_keys())

    plan = happ_sub.plan_sync(happ_sub_repo, entries, "4.8.0")
    assert plan.drift is True
    assert plan.generation == 2
    assert plan.branch == "keys/gen2-4.8.0"
    assert len(plan.changed_ids) == 90

    written = happ_sub.apply_sync(happ_sub_repo, plan, entries)
    assert [p.name for p in written] == ["gen2.rs", "mod.rs"]
    assert happ_sub.load_tables(happ_sub_repo)[-1].entries == entries

    # Once merged, the same table is recognised instead of producing gen3.
    again = happ_sub.plan_sync(happ_sub_repo, entries, "4.8.1")
    assert again.drift is False
    assert again.matched == "gen2"


def _happ_signers(version: str = "4.7.1") -> happ_sub.Signers:
    current = happ_sub.parse_signers_rs(SIGNERS_RS)
    return happ_sub.Signers(scheme=current.scheme, certs=current.certs, apk_version=version)


def test_same_signers_from_newer_release_is_not_drift(happ_sub_repo: Path) -> None:
    entries = happ_sub.table_from_keys_json(_reference_keys())
    plan = happ_sub.plan_sync(happ_sub_repo, entries, "4.8.0", _happ_signers("4.8.0"))

    assert plan.drift is False
    assert plan.signers_drift is False
    assert happ_sub.apply_sync(happ_sub_repo, plan, entries) == []


def test_signer_drift_regenerates_signers_rs_once(happ_sub_repo: Path) -> None:
    entries = happ_sub.table_from_keys_json(_reference_keys())
    fake = happ_sub.Signers(scheme="v3", certs=(FAKE_CERT,), apk_version="4.8.0")

    plan = happ_sub.plan_sync(happ_sub_repo, entries, "4.8.0", fake)
    assert plan.drift is True
    assert (plan.keys_drift, plan.signers_drift) == (False, True)
    assert plan.matched == "gen1"
    assert plan.branch == "signers/4.8.0"
    assert plan.title == "feat(device): update the signing certificate from Happ 4.8.0"
    assert plan.previous_signers == _happ_signers()
    assert plan.device_happ_version == "4.7.1"

    written = happ_sub.apply_sync(happ_sub_repo, plan, entries)
    device = happ_sub_repo / "src" / "device"
    assert written == [device / "signers.rs", device / "mod.rs"]
    assert (device / "signers.rs").read_text(encoding="utf-8") == happ_sub.render_signers_rs(fake)
    assert happ_sub.load_signers(happ_sub_repo) == fake
    mod_rs = (device / "mod.rs").read_text(encoding="utf-8")
    assert mod_rs == happ_sub.update_device_pins(DEVICE_MOD_RS, fake)
    assert HAPP_CERT_SHA256 not in mod_rs
    assert not (happ_sub_repo / "src" / "keys" / "gen2.rs").exists()

    # Once merged, the same certificate is recognised.
    assert happ_sub.plan_sync(happ_sub_repo, entries, "4.8.1", fake).drift is False


def test_key_and_signer_drift_share_one_change(happ_sub_repo: Path) -> None:
    entries = happ_sub.table_from_keys_json(_rotated_keys())
    fake = happ_sub.Signers(scheme="v2", certs=(FAKE_CERT,), apk_version="4.8.0")

    plan = happ_sub.plan_sync(happ_sub_repo, entries, "4.8.0", fake)
    assert (plan.keys_drift, plan.signers_drift) == (True, True)
    assert plan.branch == "keys/gen2-4.8.0"
    assert plan.title == "feat(keys): add generation 2 body keys and the signing certificate from Happ 4.8.0"

    written = happ_sub.apply_sync(happ_sub_repo, plan, entries)
    assert [str(p.relative_to(happ_sub_repo)) for p in written] == [
        "src/keys/gen2.rs",
        "src/keys/mod.rs",
        "src/device/signers.rs",
        "src/device/mod.rs",
    ]


def test_sync_digest_covers_signers(happ_sub_repo: Path) -> None:
    entries = happ_sub.table_from_keys_json(_rotated_keys())
    keys_only = happ_sub.plan_sync(happ_sub_repo, entries, "4.8.0", _happ_signers("4.8.0"))
    rotated = happ_sub.plan_sync(
        happ_sub_repo, entries, "4.8.0", happ_sub.Signers(scheme="v2", certs=(FAKE_CERT,), apk_version="4.8.0")
    )
    without = happ_sub.plan_sync(happ_sub_repo, entries, "4.8.0")

    assert keys_only.table_sha256 == rotated.table_sha256 == without.table_sha256
    assert len({keys_only.sync_sha256, rotated.sync_sha256, without.sync_sha256}) == 3


def test_failed_device_edit_writes_nothing(happ_sub_repo: Path) -> None:
    entries = happ_sub.table_from_keys_json(_rotated_keys())
    device_mod = happ_sub_repo / "src" / "device" / "mod.rs"
    device_mod.write_text(DEVICE_MOD_RS.replace("fn signers_digest_pinned", "fn digest_pinned"), encoding="utf-8")
    fake = happ_sub.Signers(scheme="v2", certs=(FAKE_CERT,), apk_version="4.8.0")

    plan = happ_sub.plan_sync(happ_sub_repo, entries, "4.8.0", fake)
    with pytest.raises(happ_sub.HappSubFormatError, match="signers_digest_pinned"):
        happ_sub.apply_sync(happ_sub_repo, plan, entries)
    assert not (happ_sub_repo / "src" / "keys" / "gen2.rs").exists()
    assert (happ_sub_repo / "src" / "device" / "signers.rs").read_text(encoding="utf-8") == SIGNERS_RS


def _write_extraction(tmp_path: Path, keys: dict[str, str], certs: list[bytes], all_passed: bool = True) -> list[str]:
    (tmp_path / "keys.json").write_text(json.dumps(keys), encoding="utf-8")
    meta = {
        "app_version": "4.8.0",
        "versionCode": 480,
        "apk_sha256": "ab" * 32,
        "expected_certificate_digest": "g+Uz1USttQp3T0c146yMV1OLJDI=",
    }
    (tmp_path / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    report = {
        "all_passed": all_passed,
        "warnings_count": 1,
        "checks": {
            "certificate_digest": {"passed": True, "is_warning": False, "error": None},
            "upstream_doc_anchor": {"passed": False, "is_warning": True, "error": "key02 differs"},
        },
    }
    (tmp_path / "report.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "signers.json").write_text(json.dumps(_signers_json(certs, version="4.8.0")), encoding="utf-8")
    return [f"--{name}={tmp_path / name}.json" for name in ("keys", "meta", "report", "signers")]


def _run_sync(repo: Path, args: list[str], pr_body: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    code = main(
        [
            "happ-sub-sync",
            *args,
            "--repo",
            str(repo),
            "--write",
            "--pr-body",
            str(pr_body),
            "--run-url",
            "https://github.com/o/r/actions/runs/1",
        ]
    )
    assert code == 0
    return json.loads(capsys.readouterr().out)


def test_cli_sync_writes_files_and_pr_body(
    happ_sub_repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _write_extraction(tmp_path, _rotated_keys(), list(_happ_signers().certs))
    pr_body = tmp_path / "pr.md"

    result = _run_sync(happ_sub_repo, args, pr_body, capsys)

    assert result["drift"] is True
    assert result["signers_drift"] is False
    assert result["branch"] == "keys/gen2-4.8.0"
    assert result["written"] == ["src/keys/gen2.rs", "src/keys/mod.rs"]
    body = pr_body.read_text(encoding="utf-8")
    assert "`" + "ab" * 32 + "`" in body
    assert "https://github.com/o/r/actions/runs/1" in body
    assert "| `upstream_doc_anchor` | warning: key02 differs |" in body
    assert happ_sub.SIGNERS_SECTION not in body
    assert f"<!-- happ-sub-sync-sha256: {result['sync_sha256']} -->" in body


def test_cli_sync_signer_drift_pr_body(happ_sub_repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    args = _write_extraction(tmp_path, _reference_keys(), [FAKE_CERT])
    pr_body = tmp_path / "pr.md"

    result = _run_sync(happ_sub_repo, args, pr_body, capsys)

    assert (result["drift"], result["keys_drift"], result["signers_drift"]) == (True, False, True)
    assert result["branch"] == "signers/4.8.0"
    assert result["written"] == ["src/device/signers.rs", "src/device/mod.rs"]
    body = pr_body.read_text(encoding="utf-8")
    assert "## Signing certificate changed: SSAID values computed by clients change for new installs" in body
    assert f"`{HAPP_CERT_SHA256}` (Happ 4.7.1)" in body
    assert f"`{hashlib.sha256(FAKE_CERT).hexdigest()}` (Happ 4.8.0)" in body
    assert "`HAPP_VERSION` in `src/device/mod.rs` is still 4.7.1" in body
    assert "Keys that differ" not in body
    assert f"<!-- happ-sub-sync-sha256: {result['sync_sha256']} -->" in body


def test_cli_sync_refuses_failed_extraction(happ_sub_repo: Path, tmp_path: Path) -> None:
    args = _write_extraction(tmp_path, _rotated_keys(), [FAKE_CERT], all_passed=False)
    assert main(["happ-sub-sync", *args, "--repo", str(happ_sub_repo), "--write"]) == 1
    assert not (happ_sub_repo / "src" / "keys" / "gen2.rs").exists()
    assert (happ_sub_repo / "src" / "device" / "signers.rs").read_text(encoding="utf-8") == SIGNERS_RS
