"""APK signing certificate extraction and digest computation."""

from __future__ import annotations

import base64
import hashlib
from typing import TYPE_CHECKING, Any

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


def _leaf_certs(signers: list[Any] | None, scheme: str) -> list[bytes]:
    # Android builds `PackageInfo.signatures` from the first certificate of each signer's chain.
    certs: list[bytes] = []
    for signer in signers or []:
        chain = signer.signed_data.certificates
        if not chain:
            raise ValueError(f"APK Signature Scheme {scheme} signer carries no certificate")
        certs.append(bytes(chain[0]))
    return certs


def get_ssaid_signers(apk: APK) -> tuple[str, list[bytes]]:
    """Return the scheme and DER certificates Android feeds into the SSAID HMAC, in signer order.

    Android verifies only the highest scheme present (v3.1, v3, v2, v1) and takes its signers,
    never mixing schemes. A v3/v3.1 block may hold several signers for disjoint SDK ranges, of
    which the platform picks one; that selection is not modelled, so such an APK is rejected.
    """
    if apk.is_signed_v31():
        apk.get_certificates_der_v31()
        scheme, certs = "v3.1", _leaf_certs(apk._v31_signing_data, "v3.1")
    elif apk.is_signed_v3():
        apk.get_certificates_der_v3()
        scheme, certs = "v3", _leaf_certs(apk._v3_signing_data, "v3")
    elif apk.is_signed_v2():
        apk.get_certificates_der_v2()
        scheme, certs = "v2", _leaf_certs(apk._v2_signing_data, "v2")
    elif apk.is_signed_v1():
        names = apk.get_signature_names()
        scheme, certs = "v1", [der for name in names if (der := apk.get_certificate_der(name)) is not None]
        if len(certs) != len(names):
            raise ValueError("JAR signature does not verify against its certificate")
    else:
        raise ValueError("APK is not signed")
    if not certs:
        raise ValueError(f"APK Signature Scheme {scheme} block has no signer")
    if scheme.startswith("v3") and len(certs) != 1:
        raise ValueError(f"APK Signature Scheme {scheme} block has {len(certs)} signers, expected 1")
    return scheme, certs


def signers_export(scheme: str, certs: list[bytes], apk_version: str) -> dict[str, Any]:
    """Build the `signers.json` document that happ-sub-sync compares with happ-sub."""
    return {
        "scheme": scheme,
        "apk_version": apk_version,
        "certs": [base64.b64encode(der).decode("ascii") for der in certs],
        "sha256": [hashlib.sha256(der).hexdigest() for der in certs],
    }
