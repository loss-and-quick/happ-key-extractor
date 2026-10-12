"""APK signing certificate extraction and digest computation."""

from __future__ import annotations

import base64
import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androguard.core.apk import APK


def get_apk_cert_digest(apk: APK) -> str:
    """Extract first signing certificate from APK (v2/v3 signing block) and return base64(SHA-1(cert))."""
    certs = apk.get_certificates()
    if not certs:
        raise ValueError("No signing certificates found in APK")
    cert = certs[0]
    der_bytes = cert.dump()
    sha1_digest = hashlib.sha1(der_bytes).digest()
    return base64.b64encode(sha1_digest).decode("ascii")


def get_apk_cert_sha1_hex(apk: APK) -> str:
    """Extract first signing certificate from APK and return hex(SHA-1(cert))."""
    certs = apk.get_certificates()
    if not certs:
        raise ValueError("No signing certificates found in APK")
    cert = certs[0]
    der_bytes = cert.dump()
    return hashlib.sha1(der_bytes).hexdigest()
