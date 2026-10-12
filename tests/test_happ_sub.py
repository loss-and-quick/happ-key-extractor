"""happ-sub key table parser and generator, checked against snapshots of happ-sub's sources."""

import json
import shutil
from pathlib import Path

import pytest

from happ_keys import happ_sub
from happ_keys.cli import main

DATA_DIR = Path(__file__).parent / "data"
SNAPSHOT_DIR = DATA_DIR / "happ-sub"
GEN1_RS = (SNAPSHOT_DIR / "gen1.rs").read_text(encoding="utf-8")
MOD_RS = (SNAPSHOT_DIR / "mod.rs").read_text(encoding="utf-8")


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


@pytest.fixture
def happ_sub_repo(tmp_path: Path) -> Path:
    keys_dir = tmp_path / "happ-sub" / "src" / "keys"
    keys_dir.mkdir(parents=True)
    shutil.copy(SNAPSHOT_DIR / "gen1.rs", keys_dir / "gen1.rs")
    shutil.copy(SNAPSHOT_DIR / "mod.rs", keys_dir / "mod.rs")
    return tmp_path / "happ-sub"


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


def _write_extraction(tmp_path: Path, keys: dict[str, str], all_passed: bool = True) -> list[str]:
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
    return [f"--{name}={tmp_path / name}.json" for name in ("keys", "meta", "report")]


def test_cli_sync_writes_files_and_pr_body(
    happ_sub_repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _write_extraction(tmp_path, _rotated_keys())
    pr_body = tmp_path / "pr.md"

    code = main(
        [
            "happ-sub-sync",
            *args,
            "--repo",
            str(happ_sub_repo),
            "--write",
            "--pr-body",
            str(pr_body),
            "--run-url",
            "https://github.com/o/r/actions/runs/1",
        ]
    )

    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["drift"] is True
    assert result["branch"] == "keys/gen2-4.8.0"
    assert result["written"] == ["src/keys/gen2.rs", "src/keys/mod.rs"]
    body = pr_body.read_text(encoding="utf-8")
    assert "`" + "ab" * 32 + "`" in body
    assert "https://github.com/o/r/actions/runs/1" in body
    assert "| `upstream_doc_anchor` | warning: key02 differs |" in body
    assert f"<!-- happ-keys-table-sha256: {result['table_sha256']} -->" in body


def test_cli_sync_refuses_failed_extraction(happ_sub_repo: Path, tmp_path: Path) -> None:
    args = _write_extraction(tmp_path, _rotated_keys(), all_passed=False)
    assert main(["happ-sub-sync", *args, "--repo", str(happ_sub_repo), "--write"]) == 1
    assert not (happ_sub_repo / "src" / "keys" / "gen2.rs").exists()
