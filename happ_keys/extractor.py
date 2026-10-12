"""Main key extraction pipeline coordinator."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from loguru import logger

    logger.disable("androguard")
except ImportError:
    pass

from androguard.core.apk import APK
from androguard.core.dex import DEX

from happ_keys.apk_signer import get_apk_cert_digest, get_ssaid_signers, signers_export
from happ_keys.combine import combine_keys
from happ_keys.dex_parser import parse_dex_structure
from happ_keys.native import UnicornNativeDumper
from happ_keys.stego import decode_stego_entries
from happ_keys.user_agent import check_user_agent_builder
from happ_keys.verifiers import (
    CheckResult,
    VerificationReport,
    verify_certificate_digest,
    verify_domain_registry_asset,
    verify_key_table_shape,
    verify_steganography_payloads,
    verify_upstream_doc_anchor,
)

PINNED_CRYPT5_COMMIT: str = "8d0b97b1875446abb16a0d1b62492a404e766860"


@dataclass
class ExtractionResult:
    keys: dict[str, str]
    meta: dict[str, Any]
    report: VerificationReport
    signers: dict[str, Any]

    def save(
        self,
        output_keys_path: Path | str | None,
        meta_path: Path | str | None = None,
        signers_path: Path | str | None = None,
    ) -> None:
        if output_keys_path is not None:
            p = Path(output_keys_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            # Write JSON matching reference formatting: indent=2, sort_keys=True, no trailing newline
            content = json.dumps(self.keys, indent=2, sort_keys=True)
            p.write_text(content, encoding="utf-8")

        if meta_path is not None:
            mp = Path(meta_path)
            mp.parent.mkdir(parents=True, exist_ok=True)
            content = json.dumps(self.meta, indent=2, sort_keys=True)
            mp.write_text(content, encoding="utf-8")

        if signers_path is not None:
            sp = Path(signers_path)
            sp.parent.mkdir(parents=True, exist_ok=True)
            sp.write_text(json.dumps(self.signers, indent=2) + "\n", encoding="utf-8")


class Extractor:
    """Extracts Happ subscription-body keys and verifies gates using pure Python + Unicorn."""

    def __init__(self, apk_path: str | Path) -> None:
        self.apk_path = Path(apk_path)
        if not self.apk_path.is_file():
            raise FileNotFoundError(f"APK file not found: {self.apk_path}")

        # Compute APK sha256
        raw_apk = self.apk_path.read_bytes()
        self.apk_sha256 = hashlib.sha256(raw_apk).hexdigest()

        # Load APK and DEX files
        self.apk = APK(str(self.apk_path))
        self.dex_objects = [DEX(b) for b in self.apk.get_all_dex()]
        self.arsc = self.apk.get_android_resources()

        self.version_name = self.apk.get_androidversion_name() or "unknown"
        self.version_code = self.apk.get_androidversion_code() or 0

    def extract(self) -> ExtractionResult:
        """Run the full extraction and verification pipeline."""
        # 1. Parse DEX structure
        structure = parse_dex_structure(self.apk, self.dex_objects)

        # 2. Extract Native strings via Unicorn
        so_data = self.apk.get_file("lib/arm64-v8a/liberror-code.so")
        if not so_data:
            # Fallback check
            so_data = self.apk.get_file("lib/armeabi-v7a/liberror-code.so")
            if not so_data:
                raise FileNotFoundError("liberror-code.so not found in APK")
            raise NotImplementedError("32-bit armeabi-v7a liberror-code.so requires arm32 Unicorn harness")

        native_dumper = UnicornNativeDumper(so_data)

        # Collect needed codes: 3 id lists + kz1.c ids (35, 1059)
        needed_codes = set(structure.list1) | set(structure.list2) | set(structure.list3)
        needed_codes.add(structure.kz1_c_key_id)
        needed_codes.add(structure.kz1_c_iv_id)

        native_strings: dict[int, str] = {}
        for code in needed_codes:
            native_strings[code] = native_dumper.get_string(code)

        # 3. Decode PNG stego strings
        stego_strings = decode_stego_entries(self.apk, self.arsc, structure.stego_pairs)

        # 4. Combine layers into final keys
        iv_bytes = structure.iv_literal.encode("utf-8")
        keys = combine_keys(
            structure.list1,
            structure.list2,
            structure.list3,
            native_strings,
            stego_strings,
            iv=iv_bytes,
        )

        # 5. Run verification checks
        cert_digest = get_apk_cert_digest(self.apk)
        chk_cert = verify_certificate_digest(structure.anti_tamper_blob, cert_digest, iv=iv_bytes)
        chk_shape = verify_key_table_shape(keys)
        chk_domain_reg = verify_domain_registry_asset(
            structure.data_result_bytes,
            native_strings[structure.kz1_c_key_id],
            structure.kz1_c_literal,
            native_strings[structure.kz1_c_iv_id],
        )
        chk_stego = verify_steganography_payloads(stego_strings, expected_count=len(structure.stego_pairs))
        chk_anchor = verify_upstream_doc_anchor(keys)
        user_agent, chk_user_agent = check_user_agent_builder(
            self.dex_objects, self.version_name, int(self.version_code)
        )

        checks: dict[str, CheckResult] = {
            "certificate_digest": chk_cert,
            "key_table_shape": chk_shape,
            "domain_registry_asset": chk_domain_reg,
            "steganography_payloads": chk_stego,
            "upstream_doc_anchor": chk_anchor,
            "user_agent_builder": chk_user_agent,
        }

        # upstream_doc_anchor mismatch is treated as a warning (keys may rotate), not failure
        critical_passed = chk_cert.passed and chk_shape.passed and chk_domain_reg.passed and chk_stego.passed
        warning_count = sum(not c.passed for c in (chk_anchor, chk_user_agent))

        kz1_c_full_key = native_strings[structure.kz1_c_key_id] + structure.kz1_c_literal
        kz1_c_full_iv = native_strings[structure.kz1_c_iv_id]

        data_result_groups = chk_domain_reg.details.get("group_count", 0) if chk_domain_reg.details else 0

        meta: dict[str, Any] = {
            "app_version": self.version_name,
            "versionCode": self.version_code,
            "apk_sha256": self.apk_sha256,
            "iv_literal": structure.iv_literal,
            "kz1_c_key": kz1_c_full_key,
            "kz1_c_iv": kz1_c_full_iv,
            "expected_certificate_digest": cert_digest,
            "group_counts": {
                "body_keys": len(keys),
                "data_result_groups": data_result_groups,
            },
            "ua_build_stamp": user_agent.build_stamp if user_agent else None,
            "ua_suffix": user_agent.suffix if user_agent else None,
            "upstream_crypt5_commit": PINNED_CRYPT5_COMMIT,
            "patch_offset": hex(native_dumper.discovered_patch_offset)
            if native_dumper.discovered_patch_offset
            else None,
            "target_vaddr": hex(native_dumper.discovered_target_vaddr)
            if native_dumper.discovered_target_vaddr
            else None,
        }

        report = VerificationReport(
            all_passed=critical_passed,
            warnings_count=warning_count,
            checks=checks,
        )

        scheme, certs = get_ssaid_signers(self.apk)
        signers = signers_export(scheme, certs, self.version_name)

        return ExtractionResult(keys=keys, meta=meta, report=report, signers=signers)
