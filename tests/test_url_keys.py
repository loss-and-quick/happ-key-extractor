"""Offline decryption of captured happ://crypt5/ links with the pinned RSA keys."""

from pathlib import Path

from happ_keys.crypt5_verifier import verify_fixtures

DATA_DIR = Path(__file__).parent / "data"

EXPECTED_PLAINTEXTS = {
    "resp-3.json": "https://example.com/probe-3?pad=xxxxxxxxxxxxxxxxxxxxx",
    "resp-4.json": "https://example.com/probe-4?pad=xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "resp-5.json": "https://example.com/probe-5?pad=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "resp-6.json": "https://example.com/probe-6?pad=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "resp-api.json": "https://example.com/happ-crypt5-probe-2",
}


def test_offline_crypt5_fixtures_decryption() -> None:
    results = verify_fixtures(DATA_DIR / "crypt5", DATA_DIR / "crypt5_keys.json")

    assert sorted(results) == sorted(EXPECTED_PLAINTEXTS)
    for name, expected in EXPECTED_PLAINTEXTS.items():
        assert results[name]["success"] is True
        assert results[name]["decrypted"] == expected, name
