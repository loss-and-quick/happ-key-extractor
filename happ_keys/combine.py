"""AES-GCM decryption primitive and layer combination."""

from __future__ import annotations

import base64
from collections.abc import Mapping

from Crypto.Cipher import AES

DEFAULT_IV: bytes = b"kkkkkkkkkkkk"


def kz1_b(ciphertext_b64: str, key_utf8: str, tag_b64: str, iv: bytes = DEFAULT_IV) -> bytes:
    """Verbatim kz1.b: AES-128-GCM decryption with iv and 16-byte tag."""
    ct = base64.b64decode(ciphertext_b64)
    tag = base64.b64decode(tag_b64)
    cipher = AES.new(key_utf8.encode("utf-8"), AES.MODE_GCM, nonce=iv, mac_len=16)
    return cipher.decrypt_and_verify(ct, tag)


def combine_keys(
    list1: list[int],
    list2: list[int],
    list3: list[int],
    native_strings: Mapping[int, str],
    stego_strings: Mapping[int, str],
    iv: bytes = DEFAULT_IV,
) -> dict[str, str]:
    """Combine native JNI strings and PNG stego strings into 90 final keys.

    Formula: entry[i] = kz1.b(ct=S1[i], key=S2[i], tag=S3[i], iv=iv) + stego[i]
    Returns dict sorted by keyid ("key01" .. "key90").
    """
    if not (len(list1) == len(list2) == len(list3)):
        raise ValueError(f"List lengths do not match: {len(list1)}, {len(list2)}, {len(list3)}")

    count = len(list1)
    keys: dict[str, str] = {}

    for i in range(count):
        code1 = list1[i]
        code2 = list2[i]
        code3 = list3[i]

        s1 = native_strings[code1]
        s2 = native_strings[code2]
        s3 = native_strings[code3]

        layer2 = kz1_b(s1, s2, s3, iv=iv).decode("utf-8")
        layer3 = stego_strings[i]
        entry = layer2 + layer3

        keyid = entry.split(":")[0]
        keys[keyid] = entry

    return dict(sorted(keys.items()))
