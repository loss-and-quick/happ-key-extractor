"""Weekly crypt5 live rotation canary.

Generates a fresh happ://crypt5/ link via the public generator API (crypto.happ.su)
for a neutral target URL, and verifies that the pinned keyring decrypts it.
Runs strictly once per workflow invocation without aggressive retries.
"""

import json
import random
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from happ_keys.crypt5_verifier import _swap_block_halves, decrypt_crypt5_link

GENERATOR_API_URL: str = "https://crypto.happ.su/api-v2.php"

BROWSER_USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.0 Safari/605.1.15",
]


def run_crypt5_canary(keys_path: Path | str) -> int:
    keys_file = Path(keys_path)
    if not keys_file.is_file():
        print(f"Error: Keyring file not found: {keys_file}", file=sys.stderr)
        return 2

    with open(keys_file, encoding="utf-8") as f:
        keyring = json.load(f)

    # 1. Prepare neutral probe URL
    probe_id = uuid.uuid4().hex[:12]
    target_url = f"https://example.com/sub/canary-{probe_id}"
    user_agent = random.choice(BROWSER_USER_AGENTS)

    print(f"Target URL:  {target_url}")
    print(f"User-Agent:  {user_agent}")

    # 2. Single request to public generator
    req_body = json.dumps({"url": target_url}).encode("utf-8")
    req = urllib.request.Request(
        GENERATOR_API_URL,
        data=req_body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": user_agent,
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            status = resp.status
            if status != 200:
                print(f"::warning::Generator returned HTTP {status} — skipping canary run.")
                return 0
            resp_bytes = resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"::warning::Generator API unreachable ({exc}) — skipping canary run without failure.")
        return 0

    try:
        resp_data = json.loads(resp_bytes.decode("utf-8"))
        encrypted_link = resp_data.get("encrypted_link")
        if not encrypted_link or not isinstance(encrypted_link, str):
            print(f"::warning::Generator response missing encrypted_link — skipping: {resp_data}")
            return 0
    except Exception as exc:
        print(f"::warning::Failed to parse generator JSON ({exc}) — skipping canary run.")
        return 0

    print(f"Encrypted Link: {encrypted_link[:40]}...")

    # 3. Marker inspection
    payload = encrypted_link.strip().removeprefix("happ://crypt5/")
    swapped = _swap_block_halves(payload.encode("ascii"))
    marker = (swapped[:4] + swapped[-4:]).decode("ascii", errors="replace")
    print(f"Observed Marker: {marker!r}")

    if marker not in keyring:
        print(f"::error::Marker {marker!r} is NOT present in the pinned {len(keyring)}-key keyring!")
        return 1

    # 4. Decrypt and assert plaintext match
    try:
        decrypted_url = decrypt_crypt5_link(encrypted_link, keyring)
    except Exception as exc:
        print(f"::error::Decryption of live canary link failed: {exc}")
        return 1

    if decrypted_url != target_url:
        print(f"::error::Decrypted URL mismatch: {decrypted_url!r} != {target_url!r}")
        return 1

    print(f"SUCCESS: Decrypted URL matches target exactly (marker: {marker}).")
    return 0


if __name__ == "__main__":
    keyring_arg = sys.argv[1] if len(sys.argv) > 1 else "tests/data/crypt5_keys.json"
    sys.exit(run_crypt5_canary(keyring_arg))
