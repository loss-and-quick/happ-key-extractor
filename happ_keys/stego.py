"""Port of Happ's kz1.a(int index, int resId) PNG steganography."""

from __future__ import annotations

import io
from collections import deque
from typing import TYPE_CHECKING, Any

from PIL import Image

if TYPE_CHECKING:
    from androguard.core.apk import APK


def _chunks_from_pixel(img: Image.Image, x: int, y: int) -> tuple[int, int]:
    """Each pixel contributes 2 bits from blue and 2 bits from green:
    (b & 3), (g & 3).
    """
    p = img.getpixel((x, y))
    # p can be (r, g, b) or (r, g, b, a)
    g = p[1]
    b = p[2]
    return (b & 3), (g & 3)


def decode_image(img: Image.Image) -> str | None:
    """Decode a steganographic string from an image using Happ's algorithm.

    Format: "!encoded!" + <decimal length> + "!" + <payload chars>.
    Traversal: column-major (x outer, y inner).
    Returns decoded payload string, or None if magic check fails.
    """
    img_rgba = img.convert("RGBA")
    w, h = img_rgba.size

    # Loop 0: read 9 chars (18 pixels) for magic "!encoded!"
    buf: list[str] = []
    q: deque[int] = deque()
    i6 = 0
    outer_break = False
    for x in range(w):
        if outer_break:
            break
        for y in range(h):
            if i6 == 45:
                outer_break = True
                break
            c0, c1 = _chunks_from_pixel(img_rgba, x, y)
            q.append(c0)
            q.append(c1)
            if len(q) >= 4:
                a, b, c, d = q.popleft(), q.popleft(), q.popleft(), q.popleft()
                buf.append(chr((a << 6) | (b << 4) | (c << 2) | d))
                i6 += 1
            i6 += 2

    if "".join(buf) != "!encoded!":
        return None

    # Loop 2: skip 18 pixels (the magic), read decimal length until '!'
    digits: list[str] = []
    q2: deque[int] = deque()
    i9 = 0
    broke = False
    for x in range(w):
        if broke:
            break
        for y in range(h):
            if i9 < 18:
                i9 += 1
                continue
            c0, c1 = _chunks_from_pixel(img_rgba, x, y)
            q2.append(c0)
            q2.append(c1)
            if len(q2) < 4:
                continue
            a, b, c, d = q2.popleft(), q2.popleft(), q2.popleft(), q2.popleft()
            ch = chr((a << 6) | (b << 4) | (c << 2) | d)
            if ch == "!":
                broke = True
                break
            digits.append(ch)

    if not digits:
        return None

    try:
        length = int("".join(digits))
    except ValueError:
        return None

    # Loop 4: skip magic + digits + delim ((digits_len + 1) * 2 + 18 pixels), read `length` chars
    skip = (len(digits) + 1) * 2 + 18
    payload: list[str] = []
    q3: deque[int] = deque()
    skipped = 0
    pixels_read = 0
    done = False
    for x in range(w):
        if done:
            break
        for y in range(h):
            if skipped < skip:
                skipped += 1
                continue
            if pixels_read == 2 * length:
                done = True
                break
            c0, c1 = _chunks_from_pixel(img_rgba, x, y)
            q3.append(c0)
            q3.append(c1)
            pixels_read += 1
            if len(q3) >= 4:
                a, b, c, d = q3.popleft(), q3.popleft(), q3.popleft(), q3.popleft()
                payload.append(chr((a << 6) | (b << 4) | (c << 2) | d))

    return "".join(payload)


def decode_stego_entries(
    apk: APK,
    arsc: Any,
    stego_pairs: dict[int, tuple[str, int]],
) -> dict[int, str]:
    """Decode stego strings from APK for all mapped pairs.

    Returns dict mapping index -> decoded_string.
    Raises ValueError if any required index cannot be decoded.
    """
    decoded_strings: dict[int, str] = {}
    for idx, (res_name, rid) in stego_pairs.items():
        configs = arsc.get_resolved_res_configs(rid)
        if not configs:
            raise ValueError(f"Resource {res_name} (id {rid:#x}) could not be resolved in ARSC")
        # configs is a list of (config, file_path)
        file_path = configs[0][1]
        raw_bytes = apk.get_file(file_path)
        if not raw_bytes:
            raise ValueError(f"Drawable file {file_path} for {res_name} not found in APK")
        img = Image.open(io.BytesIO(raw_bytes))
        s = decode_image(img)
        if s is None:
            raise ValueError(f"Stego decode failed (!encoded! magic missing) for {res_name} (index {idx})")
        decoded_strings[idx] = s
    return decoded_strings
