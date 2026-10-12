"""Command-line interface for the Happ key extractor."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from happ_keys import apks, happ_sub


def format_text_report(report_dict: dict[str, Any]) -> str:
    """Format human-readable extraction report."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("            HAPP KEY EXTRACTION REPORT")
    lines.append("=" * 60)

    meta = report_dict.get("metadata", {})
    lines.append(f"App Version:       {meta.get('app_version')} (code {meta.get('versionCode')})")
    lines.append(f"APK SHA-256:       {meta.get('apk_sha256')}")
    lines.append(f"Signing Digest:    {meta.get('expected_certificate_digest')}")
    lines.append(f"GCM IV Literal:    {meta.get('iv_literal')}")
    lines.append(f"kz1.c Key / IV:    {meta.get('kz1_c_key')} / {meta.get('kz1_c_iv')}")
    lines.append(f"Patch Offset:      {meta.get('patch_offset')}")
    lines.append(f"Target VAddr:      {meta.get('target_vaddr')}")
    lines.append("-" * 60)
    lines.append("VERIFICATION CHECKS:")

    checks = report_dict.get("checks", {})
    for chk_id, chk in sorted(checks.items()):
        status = "PASSED" if chk.get("passed") else ("WARNING" if chk.get("is_warning") else "FAILED")
        lines.append(f"  [{status:7}] {chk_id}: {chk.get('description')}")
        if chk.get("details"):
            for k, v in chk["details"].items():
                lines.append(f"            - {k}: {v}")
        if chk.get("error"):
            lines.append(f"            ERROR: {chk['error']}")

    lines.append("-" * 60)
    all_passed = report_dict.get("all_passed", False)
    warnings = report_dict.get("warnings_count", 0)
    summary_status = "SUCCESS" if all_passed else "FAILURE"
    lines.append(f"OVERALL STATUS:    {summary_status} (Warnings: {warnings})")
    lines.append("=" * 60)
    return "\n".join(lines)


def run_extract(args: argparse.Namespace) -> int:
    apk_path = Path(args.apk)
    if not apk_path.is_file():
        print(f"Error: APK file does not exist: {apk_path}", file=sys.stderr)
        return 2

    from happ_keys.extractor import Extractor

    try:
        extractor = Extractor(apk_path)
        result = extractor.extract()
    except Exception as exc:
        print(f"Extraction failed with error: {exc}", file=sys.stderr)
        return 1

    report_dict = result.report.to_dict()

    # Save outputs if not verify-only
    if not args.verify_only:
        if args.output:
            result.save(args.output, meta_path=args.meta, signers_path=args.signers)
            print(f"Saved {len(result.keys)} keys to {args.output}", file=sys.stderr)
            if args.meta:
                print(f"Saved metadata to {args.meta}", file=sys.stderr)
            if args.signers:
                print(f"Saved signers to {args.signers}", file=sys.stderr)
        elif not args.verify_only:
            print("Warning: -o/--output not specified, keys not saved to disk", file=sys.stderr)

    # Print report
    if args.report == "json":
        print(json.dumps(report_dict, indent=2))
    else:
        print(format_text_report(report_dict))

    if not result.report.all_passed:
        return 1
    return 0


def run_verify_url_keys(args: argparse.Namespace) -> int:
    from happ_keys.crypt5_verifier import verify_fixtures

    fixtures_dir = Path(args.fixtures_dir)
    keys_file = Path(args.keys)

    if not fixtures_dir.is_dir():
        print(f"Error: Fixtures dir not found: {fixtures_dir}", file=sys.stderr)
        return 2
    if not keys_file.is_file():
        print(f"Error: Keys file not found: {keys_file}", file=sys.stderr)
        return 2

    try:
        results = verify_fixtures(fixtures_dir, keys_file)
    except Exception as exc:
        print(f"verify-url-keys failed: {exc}", file=sys.stderr)
        return 1

    all_ok = True
    print("=" * 60)
    print("        VERIFY-URL-KEYS (crypt5 fixtures)")
    print("=" * 60)
    for fn, res in results.items():
        ok = res.get("success", False)
        if not ok:
            all_ok = False
        st = "OK" if ok else "FAIL"
        print(f"  [{st:4}] {fn}: -> {res.get('decrypted')}")
    print("=" * 60)

    return 0 if all_ok else 1


def run_fetch_apks(args: argparse.Namespace) -> int:
    manifest = apks.load_manifest(Path(args.manifest))
    versions = args.version or list(manifest)
    unknown = [v for v in versions if v not in manifest]
    if unknown:
        print(f"Error: versions not in manifest: {', '.join(unknown)}", file=sys.stderr)
        return 2

    dest = Path(args.dest)
    failed = False
    for version in versions:
        try:
            path = apks.fetch_apk(manifest[version], dest, max_time=args.max_time)
        except apks.FetchError as exc:
            print(f"FAIL {exc}", file=sys.stderr)
            failed = True
            continue
        print(f"ok   {version} {path}")
    return 1 if failed else 0


def run_happ_sub_sync(args: argparse.Namespace) -> int:
    keys = json.loads(Path(args.keys).read_text(encoding="utf-8"))
    meta = json.loads(Path(args.meta).read_text(encoding="utf-8"))
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    if not report.get("all_passed"):
        print("Error: extraction report has failed critical checks; refusing to compare", file=sys.stderr)
        return 1

    entries = happ_sub.table_from_keys_json(keys)
    repo = Path(args.repo)
    try:
        signers = None
        if args.signers:
            signers = happ_sub.signers_from_json(json.loads(Path(args.signers).read_text(encoding="utf-8")))
        plan = happ_sub.plan_sync(repo, entries, str(meta["app_version"]), signers)
        written = happ_sub.apply_sync(repo, plan, entries) if args.write else []
    except happ_sub.HappSubFormatError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if plan.drift and args.pr_body:
        Path(args.pr_body).write_text(happ_sub.build_pr_body(plan, meta, report, args.run_url), encoding="utf-8")

    result = plan.to_dict()
    result["written"] = [str(p.relative_to(repo)) for p in written]
    print(json.dumps(result, indent=2))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="happ_keys",
        description="Autonomous key extractor and offline verifier for Happ Android APK",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # extract subcommand
    extract_p = subparsers.add_parser("extract", help="Extract body keys and verify checks from APK")
    extract_p.add_argument("apk", help="Path to Happ Android APK")
    extract_p.add_argument("-o", "--output", help="Output path for keys.json")
    extract_p.add_argument("--meta", help="Output path for meta.json")
    extract_p.add_argument("--signers", help="Output path for signers.json (APK signer certificates)")
    extract_p.add_argument(
        "--report",
        choices=["text", "json"],
        default="text",
        help="Report format on stdout (default: text)",
    )
    extract_p.add_argument(
        "--verify-only",
        action="store_true",
        help="Run extraction and verification checks without writing keys.json",
    )

    # verify-url-keys subcommand
    url_p = subparsers.add_parser("verify-url-keys", help="Verify offline decryption of crypt5 fixtures")
    default_fixtures = Path(__file__).parent.parent / "tests" / "data" / "crypt5"
    default_keys = Path(__file__).parent.parent / "tests" / "data" / "crypt5_keys.json"
    url_p.add_argument(
        "--fixtures-dir",
        default=str(default_fixtures),
        help=f"Directory containing resp-*.json fixtures (default: {default_fixtures})",
    )
    url_p.add_argument(
        "--keys",
        default=str(default_keys),
        help=f"Path to crypt5_keys.json (default: {default_keys})",
    )

    fetch_p = subparsers.add_parser("fetch-apks", help="Download the pinned test APKs and verify their sha256")
    fetch_p.add_argument("--dest", required=True, help="Cache directory (APKs land in <dest>/<version>/<asset>)")
    fetch_p.add_argument(
        "--manifest",
        default=str(apks.DEFAULT_MANIFEST),
        help=f"APK manifest (default: {apks.DEFAULT_MANIFEST})",
    )
    fetch_p.add_argument("--version", action="append", help="Fetch only this version (repeatable)")
    fetch_p.add_argument("--max-time", type=float, default=900.0, help="Per-download time limit in seconds")

    sync_p = subparsers.add_parser(
        "happ-sub-sync",
        help="Compare an extraction with happ-sub (key tables, signers) and generate the changed sources on drift",
    )
    sync_p.add_argument("--keys", required=True, help="keys.json written by `extract -o`")
    sync_p.add_argument("--meta", required=True, help="meta.json written by `extract --meta`")
    sync_p.add_argument("--report", required=True, help="JSON report printed by `extract --report json`")
    sync_p.add_argument("--signers", help="signers.json written by `extract --signers`; compared with signers.rs")
    sync_p.add_argument("--repo", required=True, help="Path to a happ-sub checkout")
    sync_p.add_argument(
        "--write",
        action="store_true",
        help="On drift, write gen<N>.rs and src/keys/mod.rs, or signers.rs and src/device/mod.rs",
    )
    sync_p.add_argument("--pr-body", help="Write a pull request body (Markdown) here on drift")
    sync_p.add_argument("--run-url", help="CI run URL to cite in the pull request body")

    args = parser.parse_args(argv)

    handlers = {
        "extract": run_extract,
        "verify-url-keys": run_verify_url_keys,
        "fetch-apks": run_fetch_apks,
        "happ-sub-sync": run_happ_sub_sync,
    }
    return handlers[args.subcommand](args)
