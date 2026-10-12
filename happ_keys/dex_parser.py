"""Pure-Python DEX structure parser using androguard."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX


@dataclass
class DexStructure:
    list1: list[int]
    list2: list[int]
    list3: list[int]
    stego_pairs: dict[int, tuple[str, int]]
    kz1_c_key_id: int
    kz1_c_iv_id: int
    kz1_c_literal: str
    iv_literal: str
    anti_tamper_blob: str
    data_result_bytes: bytes


def parse_dex_structure(apk: APK, dex_objects: list[DEX]) -> DexStructure:
    """Parse structure from APK DEX files by shape without hardcoded obfuscated names."""
    target_wrappers = (
        "Lsu/happ/proxyutility/util/ErrorCodeJNIWrapper;",
        "Lcom/happproxy/util/ErrorCodeJNIWrapper;",
    )

    # 1. Find the class whose <clinit> calls ErrorCodeJNIWrapper
    kz1_cls: Any = None
    for dex in dex_objects:
        for cls in dex.get_classes():
            for m in cls.get_methods():
                if m.get_name() == "<clinit>":
                    code = m.get_code()
                    if not code:
                        continue
                    for ins in code.get_bc().get_instructions():
                        out = ins.get_output()
                        if any(tw in out for tw in target_wrappers):
                            kz1_cls = cls
                            break
                if kz1_cls is not None:
                    break
            if kz1_cls is not None:
                break
        if kz1_cls is not None:
            break

    if kz1_cls is None:
        raise ValueError("Could not find class constructing error-code lists via ErrorCodeJNIWrapper")

    # 2. Extract the three id lists from kz1.<clinit>
    ints: list[int] = []
    for m in kz1_cls.get_methods():
        if m.get_name() == "<clinit>":
            bc = list(m.get_code().get_bc().get_instructions())
            for i, ins in enumerate(bc):
                if "Integer;->valueOf" in ins.get_output():
                    prev = bc[i - 1]
                    ops = prev.get_operands()
                    if len(ops) > 1:
                        ints.append(ops[1][1])
            break

    if len(ints) < 3 or len(ints) % 3 != 0:
        raise ValueError(f"Extracted {len(ints)} integers from <clinit>; expected a multiple of 3")

    list_len = len(ints) // 3
    list1 = ints[0:list_len]
    list2 = ints[list_len : 2 * list_len]
    list3 = ints[2 * list_len : 3 * list_len]

    # 3. Find static field values (for R.drawable field values)
    field_vals: dict[str, int] = {}
    for dex in dex_objects:
        for cls in dex.get_classes():
            for f in cls.get_fields():
                init_v = f.get_init_value()
                if init_v is not None:
                    field_vals[f"{cls.get_name()}->{f.get_name()}"] = init_v.get_value()

    # 4. Find (index, drawable-res-id) pairs in HappApplication.onCreate
    stego_pairs: dict[int, tuple[str, int]] = {}
    anti_tamper_blob: str | None = None

    for dex in dex_objects:
        for cls in dex.get_classes():
            if "HappApplication" in cls.get_name() and not cls.get_name().endswith("$1;"):
                for m in cls.get_methods():
                    if m.get_name() == "onCreate":
                        code = m.get_code()
                        if not code:
                            continue
                        regs: dict[int, Any] = {}
                        for ins in code.get_bc().get_instructions():
                            name = ins.get_name()
                            ops = ins.get_operands()
                            if name.startswith("const-string"):
                                s = ins.get_output().split('"')
                                if len(s) >= 2:
                                    lit_str = s[1]
                                    if "?" in lit_str and len(lit_str.split("?")) == 3:
                                        anti_tamper_blob = lit_str
                            elif name.startswith("const"):
                                regs[ops[0][1]] = ops[1][1]
                            elif name.startswith("sget"):
                                out_parts = ins.get_output().split()
                                if len(out_parts) >= 2:
                                    f_info = out_parts[-2]
                                    regs[ops[0][1]] = (f_info, field_vals.get(f_info))
                            elif name.startswith("invoke") and "(I I)V" in ins.get_output():
                                reg1, reg2 = ops[0][1], ops[1][1]
                                v1, v2 = regs.get(reg1), regs.get(reg2)
                                if isinstance(v1, int) and isinstance(v2, tuple) and v2[1] is not None:
                                    idx, (fname, fval) = v1, v2
                                elif isinstance(v2, int) and isinstance(v1, tuple) and v1[1] is not None:
                                    idx, (fname, fval) = v2, v1
                                else:
                                    continue
                                stego_pairs[idx] = (fname, fval)

    if not stego_pairs:
        raise ValueError("Could not find stego drawable calls in HappApplication.onCreate")

    # 5. Find kz1.c constants (key id, iv id, string literal)
    kz1_c_key_id: int | None = None
    kz1_c_iv_id: int | None = None
    kz1_c_literal: str | None = None
    iv_literal: str | None = None

    for m in kz1_cls.get_methods():
        code = m.get_code()
        if not code:
            continue
        bc = list(code.get_bc().get_instructions())
        # Check if method uses AES/GCM/NoPadding
        has_gcm = any("AES/GCM/NoPadding" in ins.get_output() for ins in bc)
        if not has_gcm:
            continue

        # Check if it has string literal "kkkkkkkkkkkk"
        for ins in bc:
            if "const-string" in ins.get_name():
                s = ins.get_output().split('"')
                if len(s) >= 2:
                    val = s[1]
                    if len(val) == 12 and len(set(val)) == 1:
                        iv_literal = val

        # Check if it calls ErrorCodeJNIWrapper.a(I) twice and concatenates a string
        call_ids: list[int] = []
        found_lit: str | None = None
        for i, ins in enumerate(bc):
            if any(tw in ins.get_output() for tw in target_wrappers) and "->a(I)" in ins.get_output():
                # inspect preceding instruction
                prev = bc[i - 1]
                ops = prev.get_operands()
                if len(ops) > 1 and isinstance(ops[1][1], int):
                    call_ids.append(ops[1][1])
            if "const-string" in ins.get_name():
                s = ins.get_output().split('"')
                if len(s) >= 2 and len(s[1]) > 5 and s[1] != "AES/GCM/NoPadding" and s[1] != "AES":
                    found_lit = s[1]

        if len(call_ids) >= 2 and found_lit:
            kz1_c_key_id = call_ids[0]
            kz1_c_iv_id = call_ids[1]
            kz1_c_literal = found_lit

    if kz1_c_key_id is None or kz1_c_iv_id is None or kz1_c_literal is None:
        raise ValueError("Could not find kz1.c constants in ErrorCodeJNIWrapper caller class")

    if iv_literal is None:
        iv_literal = "kkkkkkkkkkkk"

    if anti_tamper_blob is None:
        raise ValueError("Could not find anti-tamper signature blob in HappApplication.onCreate")

    # 6. Read assets/data.result bytes
    data_result_bytes = apk.get_file("assets/data.result") or b""

    return DexStructure(
        list1=list1,
        list2=list2,
        list3=list3,
        stego_pairs=stego_pairs,
        kz1_c_key_id=kz1_c_key_id,
        kz1_c_iv_id=kz1_c_iv_id,
        kz1_c_literal=kz1_c_literal,
        iv_literal=iv_literal,
        anti_tamper_blob=anti_tamper_blob,
        data_result_bytes=data_result_bytes,
    )
