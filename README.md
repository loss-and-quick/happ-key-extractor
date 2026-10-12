# happ-key-extractor

Extracts the 90 AES-128 subscription body keys from the Android client Happ (`su.happ.proxyutility`) and checks them offline. A weekly CI job runs it on the latest Happ release. If the vendor rotates the keys, the job opens a pull request that adds the new table to [happ-sub](https://github.com/loss-and-quick/happ-sub), the Rust crate that decrypts Happ subscriptions.

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

`extract` runs five offline checks. The first four are critical. The fifth only raises a warning, because a rotation is expected to change it.

| Check | What it proves |
| --- | --- |
| `certificate_digest` | Decrypts the anti-tamper blob in `HappApplication` (`key?ciphertext?tag`, AES-GCM with the IV literal). The result must equal base64(SHA-1) of the APK's signing certificate. This shows the DEX parse found the right constants and the GCM primitive is correct. |
| `key_table_shape` | Exactly 90 entries, `key01`..`key90`, each 16 bytes and prefixed with its own id. |
| `domain_registry_asset` | Decrypts `assets/data.result` with key `S(35) + literal` and IV `S(1059)`, both from the emulated native code. The output must be zstd-compressed JSON with a non-empty group map (390 groups in 4.7.1). This shows the emulator returns correct strings. |
| `steganography_payloads` | All 90 icons decode with the `!encoded!` magic. |
| `upstream_doc_anchor` | `key02` equals `key02:+]%4ij#P"/`, the test key in the vendor's provider documentation (warning only). |

Supported releases are 4.3.0 through 4.7.1, which share one table, gen1 in happ-sub. 3.26.3 and older use a different JNI epilogue and a 10-key table. The extractor rejects them with `UnsupportedCodeShapeError`.

## Usage

Requires Python 3.11+.

```sh
python -m pip install --require-hashes -r requirements.txt   # or: nix develop
```

| Command | Purpose |
| --- | --- |
| `python -m happ_keys extract Happ.apk -o keys.json --meta meta.json [--report text\|json] [--verify-only]` | Extract the table and run the checks. Exits non-zero if a critical check fails. |
| `python -m happ_keys verify-url-keys [--fixtures-dir DIR] [--keys FILE]` | Decrypt the captured `happ://crypt5/` fixtures with the pinned RSA keys. |
| `python -m happ_keys fetch-apks --dest DIR [--version V ...]` | Download the pinned test APKs into `DIR/<version>/<asset>` and verify each sha256. Files already cached and verified are not downloaded again. |
| `python -m happ_keys happ-sub-sync --keys K --meta M --report R --repo HAPP_SUB [--write] [--pr-body FILE] [--run-url URL]` | Compare an extracted table with every `src/keys/gen*.rs` in a happ-sub checkout. On drift with `--write`, it generates the next generation (see below). |
| `python -m happ_keys.canary tests/data/crypt5_keys.json` | Live crypt5 canary (network). |

`keys.json` maps each id to its entry (`{"key01": "key01:3jk#R2d&Dd", ...}`), sorted and indented by 2, with no trailing newline.

### Drift handling

`happ-sub-sync` parses the Rust tables in happ-sub, so happ-sub stays the only place the tables are kept. If the extracted table equals an existing generation, there is no drift. Otherwise, with `--write`, it:

- writes `src/keys/gen<N+1>.rs` in the same layout as `gen1.rs`;
- registers it in `src/keys/mod.rs` with `mod`, `pub use` and a `TABLE_GEN<N+1>_<version>` const whose id is `gen<N+1>-<version>`;
- puts the new table first in `ALL_TABLES`, using rustfmt's layout;
- leaves `DEFAULT_TABLE` unchanged.

The pull request body lists the APK version and sha256, the check results, the run URL and a table digest. The digest lets later runs find the open PR instead of opening a duplicate.

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
| `happ-sub/gen1.rs`, `happ-sub/mod.rs` | Snapshots of happ-sub's `src/keys/` sources, used by the generator tests. |

## CI

`.github/workflows/keys.yml` runs on push to `main`, on pull requests, every Monday at 06:00 UTC and on manual dispatch.

| Job | Runs on | What it does |
| --- | --- | --- |
| `lint-test` | all events | Ruff check and format check. Restores the pinned APKs from `actions/cache` (keyed on the hash of `tests/apks.json`), fetches any that are missing, then runs pytest with `HAPP_REQUIRE_APKS=1`. |
| `extract` | all events | Downloads the latest Happ release and checks it against the asset digest GitHub reports. Extracts and verifies, then uploads the result as an artifact. Outside pull requests, a failed extraction opens or comments on one tracking issue, and the next success closes it. |
| `happ-sub-sync` | not on pull requests | Checks out `loss-and-quick/happ-sub` and runs `happ-sub-sync`. On drift it pushes `keys/gen<N+1>-<version>` and opens a PR. If an open PR already has that branch or that table digest, the job comments on it instead. |
| `crypt5-canary` | schedule, dispatch | Generates a link through crypto.happ.su and decrypts it with `tests/data/crypt5_keys.json`. If the generator cannot be reached, the job logs a warning and passes. A decryption failure opens or comments on a tracking issue, and only a verified decryption closes it. |

The workflow pushes nothing to this repository. All jobs have `contents: read`; `extract` and `crypt5-canary` also have `issues: write`. Actions are pinned by commit SHA.

## Dependencies

`requirements.txt` is a hashed lock generated from `pyproject.toml`:

```sh
uv pip compile pyproject.toml --extra dev --universal --python-version 3.11 --generate-hashes -o requirements.txt
```

CI uses Python 3.13. `nix develop` provides the same tools from nixpkgs, and `nix flake check` runs ruff and the offline tests.

## License

MIT, see [LICENSE](LICENSE).
