# happ-key-extractor

Extracts the 90 AES-128 subscription body keys from the Android client Happ (`su.happ.proxyutility`) and checks them offline. A weekly CI job runs it on the latest Happ release. If the vendor rotates the keys or the APK signing certificate, or ships a new version, the job opens a pull request against [happ-sub](https://github.com/loss-and-quick/happ-sub), the Rust crate that decrypts Happ subscriptions and computes the SSAID Happ reports as its device id.

Happ is a closed-source fork of the GPL-3.0 client [v2rayNG](https://github.com/2dust/v2rayNG). Its subscription bodies are encrypted with AES-128-GCM under a key picked by the `?key=keyNN` URL parameter. The key table is not in the APK as plain data: the app assembles it at runtime from native code, DEX constants and pixels hidden in icons. This tool rebuilds that assembly without an Android device or emulator.

## How extraction works

Each table entry is `keyNN:<10 chars>`, 16 bytes, and the whole entry (prefix included) is the AES key. It is built from two layers:

```
entry[i] = AES-128-GCM-decrypt(ct = S(list1[i]), key = S(list2[i]), tag = S(list3[i]), iv = "kkkkkkkkkkkk")
         + stego[i]
```

`S(n)` is the string that the native method `ErrorCodeJNIWrapper.jniGetErrorMessageFromCode(n)` in `liberror-code.so` returns. `stego[i]` is a string hidden in a drawable PNG.

1. **DEX analysis** (androguard, `dex_parser.py`). The parser locates classes by shape, not by obfuscated names:
   - The class whose `<clinit>` calls `ErrorCodeJNIWrapper` holds the three id lists, 90 integers each.
   - The same class has an `AES/GCM/NoPadding` method that yields the GCM IV literal and the `data.result` key parts. Those are the ids 35 and 1059 plus the literal `|fRC77gcp0,`.
   - `HappApplication.onCreate` gives the `(index, R.drawable)` pairs for the stego icons and the anti-tamper blob. Drawable ids are resolved through the static field initialisers and `resources.arsc`.
2. **Native strings** (Unicorn, `native.py`). The lookup behind the JNI export is a 1058-case jump table whose strings are XOR-decrypted at runtime, with TLS, `pthread_once` and heap use. Executing the code is simpler than reversing it, so the extractor emulates it:
   - It loads the `PT_LOAD` segments of the arm64 `liberror-code.so` at a fixed base and applies `R_AARCH64_RELATIVE` relocations. Imported symbols (`GLOB_DAT`, `JUMP_SLOT`, `ABS64`) are bound to trampolines.
   - A code hook on the trampolines implements the libc and pthread calls the library makes in Python: `malloc`/`calloc`/`realloc`/`free`, `mem*`, `str*cmp`, `strlen`, the `pthread_key_*`, `pthread_*specific`, mutex, rwlock and condvar calls, and `__cxa_*`.
   - `pthread_once` is a small ARM64 stub, so the init routine runs as guest code. The stack canary sits at `TPIDR_EL0 + 0x28`.
   - The exported `Java_..._jniGetErrorMessageFromCode` is resolved from the dynamic symbol table, and its `b` thunk is followed to the real function.
   - The function ends in a tail call to `JNIEnv->NewStringUTF` (`ldr x8,[x19]; ldr x2,[x8,#0x538]; ...; br x2`). The extractor finds that epilogue and patches it to `mov x0, x1; nop; nop; ...; ret`, so the function returns the decrypted C string and needs no `JNIEnv`. The patch site is at `0x18e0dc` in 4.5.0 and 4.7.1 and at `0x18e3ec` in 4.3.0. A generic `ldr xN,[xM,#imm] ... br xN` search covers moved epilogues.
3. **PNG steganography** (Pillow, `stego.py`). This is a port of the app's decoder. Each pixel carries 2 bits from the blue channel and 2 bits from the green channel (the low bits). Pixels are read column by column, and four 2-bit chunks form one character. The payload format is `!encoded!<decimal length>!<payload>`.
4. **Combination** (`combine.py`). The extractor applies the formula above and sorts the result by key id.

### Verification checks

`extract` runs six offline checks. The first four are critical. The last two only raise warnings: a rotation is expected to change the doc anchor, and a missing User-Agent builder must not block key and signer sync.

| Check | What it proves |
| --- | --- |
| `certificate_digest` | Decrypts the anti-tamper blob in `HappApplication` (`key?ciphertext?tag`, AES-GCM with the IV literal). The result must equal base64(SHA-1) of the APK's signing certificate. This shows the DEX parse found the right constants and the GCM primitive is correct. |
| `key_table_shape` | Exactly 90 entries, `key01`..`key90`, each 16 bytes and prefixed with its own id. |
| `domain_registry_asset` | Decrypts `assets/data.result` with key `S(35) + literal` and IV `S(1059)`, both from the emulated native code. The output must be zstd-compressed JSON with a non-empty group map (390 groups in 4.7.1). This shows the emulator returns correct strings. |
| `steganography_payloads` | All 90 icons decode with the `!encoded!` magic. |
| `upstream_doc_anchor` | `key02` equals `key02:+]%4ij#P"/`, the test key in the vendor's provider documentation (warning only). |
| `user_agent_builder` | The method holding the `"Happ/<versionName>/"` literal yields the User-Agent build stamp and suffix (warning only). If it fails, `meta.json` records them as `null`, CI opens or comments on the issue "Happ UA builder not found", and `happ-sub-sync` leaves `release.rs` alone. |

Supported releases are 4.3.0 through 4.7.1, which share one table, gen1 in happ-sub. 3.26.3 and older use a different JNI epilogue and a 10-key table. The extractor rejects them with `UnsupportedCodeShapeError`.

## Usage

Requires Python 3.11+.

```sh
python -m pip install --require-hashes -r requirements.txt   # or: nix develop
```

| Command | Purpose |
| --- | --- |
| `python -m happ_keys extract Happ.apk -o keys.json --meta meta.json [--signers signers.json] [--report text\|json] [--verify-only]` | Extract the table and the signer certificates and run the checks. Exits non-zero if a critical check fails. |
| `python -m happ_keys verify-url-keys [--fixtures-dir DIR] [--keys FILE]` | Decrypt the captured `happ://crypt5/` fixtures with the pinned RSA keys. |
| `python -m happ_keys fetch-apks --dest DIR [--version V ...]` | Download the pinned test APKs into `DIR/<version>/<asset>` and verify each sha256. Files already cached and verified are not downloaded again. |
| `python -m happ_keys happ-sub-sync --keys K --meta M --report R [--signers S] --repo HAPP_SUB [--write] [--pr-body FILE] [--run-url URL]` | Compare an extracted table with every `src/keys/gen*.rs` and the signers with `src/device/signers.rs` in a happ-sub checkout. On drift with `--write`, it generates the changed sources (see below). |
| `python -m happ_keys incy derive --apk Incy.apk [-o incy-keymat.json]` | Derive the `incy://crypt1/` key `K1` from an INCY APK and print the asset digests, the key and its fingerprint. `-o` writes the keymat in the shape happ-sub embeds. |
| `python -m happ_keys incy decrypt 'incy://crypt1/…' [--apk Incy.apk \| --key-hex HEX]` | Decrypt one link. Without `--apk` or `--key-hex` the key comes from `tests/data/incy/incy-keymat.json`. |
| `python -m happ_keys incy verify-fixtures [--fixtures-dir DIR] [--apk Incy.apk]` | Decrypt the captured `incy://crypt1/` samples and compare them with their recorded plaintexts. |
| `python -m happ_keys.canary tests/data/crypt5_keys.json` | Live crypt5 canary (network). |

`keys.json` maps each id to its entry (`{"key01": "key01:3jk#R2d&Dd", ...}`), sorted and indented by 2, with no trailing newline.

`meta.json` also records the User-Agent release constants: `ua_build_stamp` and `ua_suffix`. Happ sends `Happ/<versionName>/<os>/<stamp><versionCode><parity><suffix>`, where `stamp` is a millisecond timestamp baked in at build time, `parity` is `6` on even and `5` on odd UTC days, and `suffix` is a two-digit literal that changes between releases (`50` in 4.7.1, `35` in 4.5.0, `38` in 4.3.0). The builder is found by its `"Happ/<versionName>/"` literal, not by class name, and its version is cross-checked against the manifest.

`signers.json` holds the certificates Android feeds into the SSAID HMAC: those of the highest signature scheme in the APK (v3.1, then v3, v2, v1), the first certificate of each signer, in signer order and never mixed across schemes. It is `{"scheme": "v2", "apk_version": "4.7.1", "certs": [base64 DER, ...], "sha256": [hex, ...]}`. Happ 4.3.0 through 4.7.1 carry one v2 signer, certificate SHA-256 `397e98abed03c5f263ffaf4e8a1043b2a59f538b99e75cf152fa05a7e8007d8d`.

### Drift handling

`happ-sub-sync` parses the Rust sources in happ-sub, so happ-sub stays the only place the tables and certificates are kept. If the extracted table equals an existing generation, the keys have not drifted. Otherwise, with `--write`, it:

- writes `src/keys/gen<N+1>.rs` in the same layout as `gen1.rs`;
- registers it in `src/keys/mod.rs` with `mod`, `pub use` and a `TABLE_GEN<N+1>_<version>` const whose id is `gen<N+1>-<version>`;
- puts the new table first in `ALL_TABLES`, using rustfmt's layout;
- leaves `DEFAULT_TABLE` unchanged.

The signers have drifted when the scheme or the certificate list differs from `HAPP_SIGNERS` in `src/device/signers.rs`; a newer `apk_version` alone is not drift. With `--write`, it:

- regenerates `signers.rs` in its generated layout, with the new scheme, certificates and `apk_version`;
- recomputes the certificate-derived pins in the `src/device/mod.rs` tests: scheme, certificate count, length and SHA-256 in `signers_digest_pinned`, and the expected SSAIDs in `ssaid_matches_vector`.

The release constants `HAPP_VERSION`, `HAPP_VERSION_CODE`, `HAPP_UA_BUILD_STAMP` and `HAPP_UA_SUFFIX` in `src/release.rs` have drifted when any of them differs from the APK. With `--write`, it rewrites their values in place and leaves the doc comments alone, so those must not name a version. It also regenerates `signers.rs` with the new `apk_version`, which `signers_digest_pinned` checks against `HAPP_VERSION`. A version-only change opens a PR on `release/<version>` with the section "Happ version updated". When the stamp is unknown, `release.rs` is skipped entirely, because a new version with the old stamp and suffix would be a User-Agent no Happ release sends. The PR body says so.

The pull request body lists the APK version and sha256, the check results, the run URL and a digest over the table, the signers and the release constants. A signer change adds the section "Signing certificate changed: SSAID values computed by clients change for new installs" with the old and new certificate digests. The digest lets later runs find the open PR instead of opening a duplicate.

## Tests

```sh
python -m happ_keys fetch-apks --dest ~/.cache/happ-apks
HAPP_APK_CACHE=~/.cache/happ-apks pytest
```

`tests/apks.json` pins the release assets the tests use: 4.7.1, 4.5.0, 4.3.0 and 3.26.3. Each entry has its GitHub release URL, size and sha256, and the sha256 equals the `digest` GitHub reports for the asset. APKs are never committed. Tests read the native library straight from the APK.

| Variable | Effect |
| --- | --- |
| `HAPP_APK_CACHE` | Directory filled by `fetch-apks`. Without it, tests that need an APK are skipped and the reason is shown with `-rs`. |
| `HAPP_REQUIRE_APKS=1` | A missing APK fails the test instead of skipping it. CI sets this. |

A cached file whose sha256 does not match always fails.

### `tests/data`

| File | Provenance |
| --- | --- |
| `keys.json` | The table extracted from Happ 4.7.1. It is identical to happ-sub's `gen1.rs`. |
| `keys-raw.tsv` | `S(n)` for ids 0..1100 from the 4.7.1 `liberror-code.so`. It was dumped independently of Unicorn: the same four-instruction patch was applied and the arm64 library ran under the Android emulator's `ndk_translation`. |
| `data.result.dec` | The decrypted and decompressed `assets/data.result` from Happ 4.7.1. |
| `crypt5_keys.json` | `crypt5_keys.json` from [KernelEditor/HappDecrypt](https://github.com/KernelEditor/HappDecrypt) at commit `8d0b97b1875446abb16a0d1b62492a404e766860`, unmodified. happ-sub ships the same file as `src/keys/url-keys.json`. |
| `crypt5/resp-*.json` | Links that crypto.happ.su generated for `https://example.com/...` probe URLs. |
| `incy/incy-crypt1-samples.json` | `incy://crypt1/` payloads: the vector the vendor pins in [INCY-DEV/incy-link-encoder](https://github.com/INCY-DEV/incy-link-encoder), plus four generated with neutral `example.com` targets. happ-sub decrypts the same file. |
| `incy/incy-keymat.json` | The two 4 KiB assets from `res/raw/incy_assets_{a,b}.bin` of Incy 3.7.0, so the fixtures verify without an APK. Identical to `assets/*.bin` in the vendor's MIT package. |
| `happ-sub/src/keys/{gen1,mod}.rs`, `happ-sub/src/device/{signers,mod}.rs`, `happ-sub/src/release.rs` | Snapshots of happ-sub's `src/keys/`, `src/device/` and `src/release.rs` sources, used by the generator tests. |

## The Incy keymat

INCY (`llc.itdev.incy`, Android 3.7.0) hides a subscription URL behind `incy://crypt1/<base64url(iv ‖ ciphertext ‖ tag)>` — AES-256-GCM with a 12-byte IV and a 16-byte tag over the JSON `{"n":<name>,"url":<url>,"v":1}`. Unlike Happ, the key is in plain sight: two 4 KiB assets in `res/raw`, from which it is one SHA-256 with no secret input.

```
K1 = SHA-256("incy" || "deep" || "crypt1" || "v2026.06" || A[1024:1056] || B[2048:2080])
```

`derive` prints the derived key and its fingerprint, which is the value the vendor asserts in all four of its reference ports (`b6bf7084…`); a keymat that does not reproduce it is an error, not a warning. Because the assets are byte-identical in the APK and in the vendor's MIT package, the key is a published constant — the vendor states plainly that this scheme is obfuscation against scanners, not secrecy. `happ-sub` implements decryption under its `incy-crypt` and `builtin-incy-keys` features, and both implementations decrypt [`tests/data/incy/incy-crypt1-samples.json`](tests/data/incy), so they cannot drift apart unnoticed.

Set `INCY_APK` to an INCY APK to check the real assets in the test suite:

```sh
INCY_APK=~/Downloads/Incy.apk pytest tests/test_incy.py
```

## CI / CD

The workflows are split across:

- `.github/workflows/ci.yml`: runs `lint-test` on pull requests, pushes to `main`, and manual dispatch.
- `.github/workflows/sync.yml`: runs `extract`, `happ-sub-sync`, and scheduled `crypt5-canary` on push to `main`, every Monday at 06:00 UTC, and on manual dispatch.

| Workflow | Job | Runs on | What it does |
| --- | --- | --- | --- |
| `ci.yml` | `lint-test` | PRs, main, dispatch | Ruff check and format check. Restores the pinned APKs from `actions/cache` (keyed on the hash of `tests/apks.json`), fetches any that are missing, then runs pytest with `HAPP_REQUIRE_APKS=1`. |
| `sync.yml` | `extract` | main, schedule, dispatch | Downloads the latest Happ release and checks it against the asset digest GitHub reports. Extracts and verifies, then uploads `keys.json`, `meta.json`, `signers.json` and the report as an artifact. A failed extraction opens or comments on one tracking issue, and the next success closes it. |
| `sync.yml` | `happ-sub-sync` | after `extract` | Checks out `loss-and-quick/happ-sub` and runs `happ-sub-sync` on the key table, the signers and the release constants. On drift it commits `src/keys`, `src/device` and `src/release.rs`, pushes `keys/gen<N+1>-<version>` (or `signers/<version>` or `release/<version>` when the keys are unchanged) and opens a PR. If an open PR already has that branch or that digest, the job comments on it instead. |
| `sync.yml` | `crypt5-canary` | schedule, dispatch | Generates a link through crypto.happ.su and decrypts it with `tests/data/crypt5_keys.json`. If the generator cannot be reached, the job logs a warning and passes. A decryption failure opens or comments on a tracking issue, and only a verified decryption closes it. |

The workflows push nothing to this repository. All jobs have `contents: read`; `extract` and `crypt5-canary` also have `issues: write`. Actions are pinned by commit SHA.

## Dependencies

`requirements.txt` is a hashed lock generated from `pyproject.toml`:

```sh
uv pip compile pyproject.toml --extra dev --universal --python-version 3.11 --generate-hashes -o requirements.txt
```

CI uses Python 3.13. `nix develop` provides the same tools from nixpkgs, and `nix flake check` runs ruff and the offline tests.

## License

MIT, see [LICENSE](LICENSE).
