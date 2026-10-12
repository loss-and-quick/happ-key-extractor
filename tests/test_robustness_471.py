"""Assert measured values for Happ 4.7.1 to catch silent mis-parses."""

from pathlib import Path

from androguard.core.apk import APK
from androguard.core.dex import DEX

from happ_keys.dex_parser import parse_dex_structure
from happ_keys.native import UnicornNativeDumper


def test_robustness_measured_values_471(apk_path: Path) -> None:
    """Verify that structure parsed from 4.7.1 matches all reverse-engineered constants."""
    apk = APK(str(apk_path))
    dex_objects = [DEX(b) for b in apk.get_all_dex()]
    structure = parse_dex_structure(apk, dex_objects)

    # 1. Three id lists: 90 elements each
    assert len(structure.list1) == 90
    assert len(structure.list2) == 90
    assert len(structure.list3) == 90
    assert structure.list1[0] == 9
    assert structure.list2[0] == 224
    assert structure.list3[0] == 98

    # 2. Stego pairs cover indices 0..89 exactly
    assert sorted(structure.stego_pairs.keys()) == list(range(90))

    # 3. kz1.c constants: ids 35 and 1059, literal "|fRC77gcp0,"
    assert structure.kz1_c_key_id == 35
    assert structure.kz1_c_iv_id == 1059
    assert structure.kz1_c_literal == "|fRC77gcp0,"

    # 4. GCM IV literal
    assert structure.iv_literal == "kkkkkkkkkkkk"

    # 5. Anti-tamper blob
    assert (
        structure.anti_tamper_blob
        == "uWM0lcVs0849kTwk?AqHnQy35aOM/ZtgUip+BrTHHLnSYBNwQAX0y2g==?os8iL1DE8Dee/5roJ+ZzsQ=="
    )

    # 6. liberror-code.so patch site and thunk addresses
    so_bytes = apk.get_file("lib/arm64-v8a/liberror-code.so")
    assert so_bytes is not None
    dumper = UnicornNativeDumper(so_bytes)

    assert dumper.discovered_patch_offset == 0x18E0DC
    assert dumper.discovered_target_vaddr == 0x18C5A0
    assert dumper.discovered_entry_vaddr == 0x19AE4C

    # 7. Decrypted constants a(35) and a(1059)
    assert dumper.get_string(35) == "CHku5"
    assert dumper.get_string(1059) == "vrbculqfahmw"
