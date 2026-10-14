"""Command-line interface for the Happ key extractor."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from happ_keys import apks, happ_sub

DEFAULT_INCY_FIXTURES = Path(__file__).parent.parent / "tests" / "data" / "incy"


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
        # A null stamp means the User-Agent builder was not found; release.rs is then left alone.
        release_unknown = meta.get("ua_build_stamp") is None
        release = None if release_unknown else happ_sub.release_from_meta(meta)

        desktop_rel = None
        if getattr(args, "desktop_deb", None):
            import happ_keys.desktop as desktop

            desktop_rel = desktop.extract_happ_desktop_from_deb(args.desktop_deb)
        elif (
            getattr(args, "desktop_version", None)
            and getattr(args, "desktop_stamp", None)
            and getattr(args, "desktop_suffix", None)
        ):
            desktop_rel = happ_sub.HappDesktopRelease(
                version=args.desktop_version,
                ua_build_stamp=args.desktop_stamp,
                ua_suffix=args.desktop_suffix,
            )

        incy_rel = None
        if getattr(args, "incy_version", None) and getattr(args, "incy_version_code", None):
            incy_rel = happ_sub.IncyAndroidRelease(version=args.incy_version, version_code=int(args.incy_version_code))

        incy_desktop_rel = None
        if getattr(args, "incy_desktop_version", None):
            incy_desktop_rel = happ_sub.IncyDesktopRelease(version=args.incy_desktop_version)

        plan = happ_sub.plan_sync(
            repo,
            entries,
            str(meta["app_version"]),
            signers,
            release,
            release_unknown,
            desktop=desktop_rel,
            incy=incy_rel,
            incy_desktop=incy_desktop_rel,
        )
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


def _incy_key(args: argparse.Namespace) -> tuple[bytes | None, str | None]:
    """Resolve the key for an incy subcommand: --key-hex, then --apk, then the bundled keymat."""
    from happ_keys import incy

    if getattr(args, "key_hex", None):
        return bytes.fromhex(args.key_hex), None
    apk = getattr(args, "apk", None)
    if apk:
        apk_path = Path(apk)
        if not apk_path.is_file():
            return None, f"APK file does not exist: {apk_path}"
        try:
            return incy.derive_key(incy.read_keymat(apk_path)), None
        except incy.IncyKeymatError as exc:
            return None, str(exc)
    if args.incy_command == "decrypt":
        try:
            return incy.derive_key(incy.read_keymat_from_fixtures(Path(args.fixtures_dir))), None
        except incy.IncyKeymatError as exc:
            return None, f"{exc} (pass --apk or --key-hex, or keep the keymat next to the fixtures)"
    return None, None


def run_incy(args: argparse.Namespace) -> int:
    from happ_keys import incy

    action = args.incy_command
    if action == "derive":
        apk = Path(args.apk)
        if not apk.is_file():
            print(f"Error: APK file does not exist: {apk}", file=sys.stderr)
            return 2
        try:
            keymat = incy.read_keymat(apk)
            key = incy.derive_key(keymat)
        except incy.IncyKeymatError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        report = keymat.to_dict()
        report["k1_hex"] = key.hex()
        report["k1_fingerprint"] = incy.fingerprint(key)
        if args.output:
            Path(args.output).write_text(incy.keymat_json(keymat), encoding="utf-8")
            print(f"Saved keymat to {args.output}", file=sys.stderr)
        print(json.dumps(report, indent=2))
        return 0

    if action == "decrypt":
        key, error = _incy_key(args)
        if error is not None:
            print(f"Error: {error}", file=sys.stderr)
            return 2
        assert key is not None
        try:
            link = incy.decrypt_link(args.link, key)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(link.to_dict(), indent=2))
        return 0

    fixtures_dir = Path(args.fixtures_dir)
    if not fixtures_dir.is_dir():
        print(f"Error: Fixtures dir not found: {fixtures_dir}", file=sys.stderr)
        return 2
    key, error = _incy_key(args)
    if error is not None:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    try:
        results = incy.verify_fixtures(fixtures_dir, key)
    except incy.IncyKeymatError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    all_ok = True
    print("=" * 60)
    print("        INCY CRYPT1 (incy://crypt1/ fixtures)")
    print("=" * 60)
    for note, res in results.items():
        ok = res.get("success", False)
        if not ok:
            all_ok = False
        st = "OK" if ok else "FAIL"
        detail = res.get("url") or res.get("error", "")
        print(f"  [{st:4}] {note}: -> {detail}")
    print("=" * 60)
    return 0 if all_ok else 1


def run_desktop_extract(args: argparse.Namespace) -> int:
    import happ_keys.desktop as desktop

    path = Path(args.path)
    if not path.is_file():
        print(f"Error: file does not exist: {path}", file=sys.stderr)
        return 2
    try:
        if args.format == "deb" or path.suffix == ".deb":
            release = desktop.extract_happ_desktop_from_deb(path)
        else:
            release = desktop.extract_happ_desktop_from_binary(path.read_bytes(), known_version=args.version)
    except desktop.DesktopExtractError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    data = {
        "version": release.version,
        "ua_build_stamp": release.ua_build_stamp,
        "ua_suffix": release.ua_suffix,
        "bundle_id_linux": release.bundle_id_linux,
        "api_version": release.api_version,
    }
    if args.output:
        Path(args.output).write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(json.dumps(data, indent=2))
    return 0


def run_release_sync(args: argparse.Namespace) -> int:
    import happ_keys.desktop as desktop

    repo = Path(args.repo)
    try:
        happ_release = None
        if args.happ_version and args.happ_version_code and args.happ_stamp and args.happ_suffix:
            happ_release = happ_sub.Release(
                version=args.happ_version,
                version_code=int(args.happ_version_code),
                ua_build_stamp=args.happ_stamp,
                ua_suffix=args.happ_suffix,
            )

        desktop_release = None
        if args.from_upstream_happ_desktop:
            info = desktop.fetch_latest_happ_desktop_release()
            asset = info.get("deb_asset")
            if not asset or not asset.get("url"):
                raise happ_sub.HappSubFormatError("latest Happ Desktop release has no downloadable .deb asset")
            deb_path = Path(args.download_to) if args.download_to else repo / ".happ-desktop.deb"
            desktop.download_asset(str(asset["url"]), deb_path)
            desktop_release = desktop.extract_happ_desktop_from_deb(deb_path)
        elif args.desktop_deb:
            desktop_release = desktop.extract_happ_desktop_from_deb(args.desktop_deb)
        elif args.desktop_version and args.desktop_stamp and args.desktop_suffix:
            desktop_release = happ_sub.HappDesktopRelease(
                version=args.desktop_version,
                ua_build_stamp=args.desktop_stamp,
                ua_suffix=args.desktop_suffix,
            )

        incy_release = None
        incy_desktop_release = None
        if args.from_upstream_incy:
            info = desktop.fetch_latest_incy_releases()
            incy_release = info["android"]
            incy_desktop_release = info["desktop"]
        else:
            if args.incy_version and args.incy_version_code:
                incy_release = happ_sub.IncyAndroidRelease(
                    version=args.incy_version,
                    version_code=int(args.incy_version_code),
                )
            if args.incy_desktop_version:
                incy_desktop_release = happ_sub.IncyDesktopRelease(version=args.incy_desktop_version)

        plan = happ_sub.plan_release_sync(
            repo,
            happ=happ_release,
            desktop=desktop_release,
            incy=incy_release,
            incy_desktop=incy_desktop_release,
        )
        written = happ_sub.apply_release_sync(repo, plan) if args.write else []
    except (happ_sub.HappSubFormatError, desktop.DesktopExtractError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if plan.drift and args.pr_body:
        Path(args.pr_body).write_text(happ_sub.build_release_pr_body(plan, args.run_url), encoding="utf-8")
    result = plan.to_dict()
    result["written"] = [str(p.relative_to(repo)) for p in written]
    print(json.dumps(result, indent=2))
    return 0


def run_upstream_releases(args: argparse.Namespace) -> int:
    import happ_keys.desktop as desktop

    result: dict[str, Any] = {}
    try:
        if args.happ_desktop or (not args.happ_desktop and not args.incy):
            result["happ_desktop"] = desktop.fetch_latest_happ_desktop_release()
        if args.incy or (not args.happ_desktop and not args.incy):
            info = desktop.fetch_latest_incy_releases()
            result["incy"] = {
                "android": {
                    "version": info["android"].version if info["android"] else None,
                    "version_code": info["android"].version_code if info["android"] else None,
                },
                "desktop": {
                    "version": info["desktop"].version if info["desktop"] else None,
                },
                "android_asset": info["android_asset"],
                "desktop_asset": info["desktop_asset"],
            }
    except desktop.DesktopExtractError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
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
    sync_p.add_argument("--desktop-deb", help="Path to Happ Desktop .deb; extracts version, stamp and suffix")
    sync_p.add_argument("--desktop-version", help="Happ Desktop version to sync into release.rs")
    sync_p.add_argument("--desktop-stamp", help="Happ Desktop User-Agent build stamp (YYMMDDHHmm)")
    sync_p.add_argument("--desktop-suffix", help="Happ Desktop User-Agent suffix")
    sync_p.add_argument("--incy-version", help="Incy Android version to sync into release.rs")
    sync_p.add_argument("--incy-version-code", type=int, help="Incy Android versionCode")
    sync_p.add_argument("--incy-desktop-version", help="Incy Desktop version to sync into release.rs")
    sync_p.add_argument("--repo", required=True, help="Path to a happ-sub checkout")
    sync_p.add_argument(
        "--write",
        action="store_true",
        help="On drift, write gen<N>.rs and src/keys/mod.rs, or signers.rs and src/device/mod.rs",
    )
    sync_p.add_argument("--pr-body", help="Write a pull request body (Markdown) here on drift")
    sync_p.add_argument("--run-url", help="CI run URL to cite in the pull request body")

    desktop_extract_p = subparsers.add_parser(
        "desktop-extract", help="Extract Happ Desktop release constants from a .deb or binary"
    )
    desktop_extract_p.add_argument("path", help="Path to Happ Desktop .deb or the Happ binary")
    desktop_extract_p.add_argument("--format", choices=["auto", "deb", "binary"], default="auto")
    desktop_extract_p.add_argument("--version", help="Known version when extracting from a raw binary")
    desktop_extract_p.add_argument("-o", "--output", help="Write the extracted JSON here")

    release_sync_p = subparsers.add_parser(
        "release-sync", help="Sync desktop and Incy release constants in happ-sub/src/release.rs"
    )
    release_sync_p.add_argument("--repo", required=True, help="Path to a happ-sub checkout")
    release_sync_p.add_argument("--happ-version", help="Happ Android version")
    release_sync_p.add_argument("--happ-version-code", type=int, help="Happ Android versionCode")
    release_sync_p.add_argument("--happ-stamp", help="Happ Android UA build stamp")
    release_sync_p.add_argument("--happ-suffix", help="Happ Android UA suffix")
    release_sync_p.add_argument("--desktop-deb", help="Path to Happ Desktop .deb")
    release_sync_p.add_argument("--desktop-version", help="Happ Desktop version")
    release_sync_p.add_argument("--desktop-stamp", help="Happ Desktop UA build stamp")
    release_sync_p.add_argument("--desktop-suffix", help="Happ Desktop UA suffix")
    release_sync_p.add_argument("--from-upstream-happ-desktop", action="store_true")
    release_sync_p.add_argument("--download-to", help="Download upstream Happ Desktop .deb here")
    release_sync_p.add_argument("--incy-version", help="Incy Android version")
    release_sync_p.add_argument("--incy-version-code", type=int, help="Incy Android versionCode")
    release_sync_p.add_argument("--incy-desktop-version", help="Incy Desktop version")
    release_sync_p.add_argument("--from-upstream-incy", action="store_true")
    release_sync_p.add_argument("--write", action="store_true", help="Write src/release.rs on drift")
    release_sync_p.add_argument("--pr-body", help="Write a pull request body (Markdown) here on drift")
    release_sync_p.add_argument("--run-url", help="CI run URL to cite in the pull request body")

    upstream_p = subparsers.add_parser("upstream-releases", help="Show the latest Happ Desktop and Incy releases")
    upstream_p.add_argument("--happ-desktop", action="store_true", help="Only query Happ Desktop")
    upstream_p.add_argument("--incy", action="store_true", help="Only query Incy")

    incy_p = subparsers.add_parser("incy", help="Derive the incy://crypt1/ key and decrypt or verify its links")
    incy_sub = incy_p.add_subparsers(dest="incy_command", required=True)

    incy_derive = incy_sub.add_parser("derive", help="Derive K1 from an INCY APK's keymat assets")
    incy_derive.add_argument("--apk", required=True, help="Path to the INCY Android APK")
    incy_derive.add_argument("-o", "--output", help="Write the keymat as JSON here (the shape happ-sub embeds)")

    incy_decrypt = incy_sub.add_parser("decrypt", help="Decrypt one incy://crypt1/ link")
    incy_decrypt.add_argument("link", help="The full incy://crypt1/ link")
    incy_decrypt.add_argument("--apk", help="Derive the key from this INCY APK instead of the fixtures")
    incy_decrypt.add_argument("--key-hex", help="Use this 32-byte key as hex instead of deriving one")
    incy_decrypt.add_argument(
        "--fixtures-dir",
        default=str(DEFAULT_INCY_FIXTURES),
        help=f"Directory holding incy-keymat.json (default: {DEFAULT_INCY_FIXTURES})",
    )

    incy_verify = incy_sub.add_parser("verify-fixtures", help="Decrypt the captured incy://crypt1/ samples")
    incy_verify.add_argument(
        "--fixtures-dir",
        default=str(DEFAULT_INCY_FIXTURES),
        help=f"Directory with the sample JSON and keymat (default: {DEFAULT_INCY_FIXTURES})",
    )
    incy_verify.add_argument("--apk", help="Derive the key from this INCY APK instead of the bundled keymat")
    incy_verify.add_argument("--key-hex", help="Use this 32-byte key as hex instead of deriving one")

    args = parser.parse_args(argv)

    handlers = {
        "extract": run_extract,
        "verify-url-keys": run_verify_url_keys,
        "fetch-apks": run_fetch_apks,
        "happ-sub-sync": run_happ_sub_sync,
        "desktop-extract": run_desktop_extract,
        "release-sync": run_release_sync,
        "upstream-releases": run_upstream_releases,
        "incy": run_incy,
    }
    return handlers[args.subcommand](args)
