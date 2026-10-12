//! Device identity Happ reports on subscription fetches: `X-HWID` (its SSAID) and `User-Agent`.

use hmac::{Hmac, Mac};
use sha2::Sha256;

mod signers;

pub use crate::release::{HAPP_UA_BUILD_STAMP, HAPP_UA_SUFFIX, HAPP_VERSION, HAPP_VERSION_CODE};
pub use crate::request::user_agent;
pub use signers::HAPP_SIGNERS;

/// Happ's Android package name.
pub const HAPP_PACKAGE: &str = "su.happ.proxyutility";

/// APK signature scheme whose certificates Android hands to the SSAID derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigScheme {
    /// JAR signing.
    V1,
    /// APK Signature Scheme v2.
    V2,
    /// APK Signature Scheme v3.
    V3,
    /// APK Signature Scheme v3.1.
    V31,
}

/// Signer certificates of the highest verified scheme of one APK, in signing-block order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerSet {
    /// Scheme the certificates come from; Android never mixes schemes.
    pub scheme: SigScheme,
    /// DER-encoded X.509 certificates.
    pub certs: &'static [&'static [u8]],
    /// APK version the certificates were extracted from.
    pub apk_version: &'static str,
}

/// Errors from [`ssaid`] and [`decode_user_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    /// The stored key is not an even-length hex string.
    InvalidKeyHex,
    /// The key is not 16 or 32 bytes; carries the length found.
    InvalidKeyLength(usize),
    /// The signer set holds no certificate.
    NoCertificates,
}

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceError::InvalidKeyHex => write!(f, "user key is not an even-length hex string"),
            DeviceError::InvalidKeyLength(n) => {
                write!(f, "user key is {n} bytes, expected 16 or 32")
            }
            DeviceError::NoCertificates => write!(f, "signer set has no certificate"),
        }
    }
}

impl std::error::Error for DeviceError {}

/// The ANDROID_ID (SSAID) Android 8+ gives an app for one user key and signer set.
pub fn ssaid(user_key: &[u8], signers: &SignerSet) -> Result<String, DeviceError> {
    // AOSP SettingsProvider.generateSsaidLocked: HMAC-SHA256 over each certificate prefixed with
    // its big-endian 32-bit length, lower-case hex, first 16 characters.
    check_key_len(user_key.len())?;
    if signers.certs.is_empty() {
        return Err(DeviceError::NoCertificates);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(user_key).expect("HMAC accepts any key length");
    for cert in signers.certs {
        mac.update(&(cert.len() as u32).to_be_bytes());
        mac.update(cert);
    }
    let digest = mac.finalize().into_bytes();
    Ok(digest[..8].iter().map(|b| format!("{b:02x}")).collect())
}

/// Decodes the `userkey` stored in `settings_ssaid.xml` (hex, 16 or 32 bytes).
pub fn decode_user_key(hex: &str) -> Result<Vec<u8>, DeviceError> {
    let hex = hex.trim().as_bytes();
    if hex.len() % 2 != 0 {
        return Err(DeviceError::InvalidKeyHex);
    }
    let key = hex
        .chunks_exact(2)
        .map(|pair| {
            let digit = |c: u8| (c as char).to_digit(16).ok_or(DeviceError::InvalidKeyHex);
            Ok(((digit(pair[0])? << 4) | digit(pair[1])?) as u8)
        })
        .collect::<Result<Vec<u8>, _>>()?;
    check_key_len(key.len())?;
    Ok(key)
}

fn check_key_len(len: usize) -> Result<(), DeviceError> {
    // Android O development builds generated 16-byte keys; current ones generate 32.
    match len {
        16 | 32 => Ok(()),
        n => Err(DeviceError::InvalidKeyLength(n)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn test_key(len: u8) -> Vec<u8> {
        (0..len).collect()
    }

    #[test]
    fn ssaid_matches_vector() {
        // Expected values computed independently with `openssl dgst -sha256 -mac HMAC`.
        assert_eq!(
            ssaid(&test_key(32), &HAPP_SIGNERS).unwrap(),
            "013b86e99e8dce53"
        );
        assert_eq!(
            ssaid(&test_key(16), &HAPP_SIGNERS).unwrap(),
            "fe3093ae240d87fd"
        );
    }

    #[test]
    fn ssaid_length_prefixes_every_cert_in_order() {
        let two = SignerSet {
            scheme: SigScheme::V3,
            certs: &[b"first" as &[u8], b"second!"],
            apk_version: "test",
        };
        assert_eq!(ssaid(&test_key(32), &two).unwrap(), "c25fff3c5500ee56");
        let swapped = SignerSet {
            certs: &[b"second!" as &[u8], b"first"],
            ..two
        };
        assert_ne!(ssaid(&test_key(32), &swapped).unwrap(), "c25fff3c5500ee56");
    }

    #[test]
    fn ssaid_rejects_bad_key_len() {
        for len in [0, 15, 24, 33] {
            assert_eq!(
                ssaid(&test_key(len), &HAPP_SIGNERS),
                Err(DeviceError::InvalidKeyLength(len as usize))
            );
        }
        let empty = SignerSet {
            certs: &[],
            ..HAPP_SIGNERS
        };
        assert_eq!(
            ssaid(&test_key(32), &empty),
            Err(DeviceError::NoCertificates)
        );
    }

    #[test]
    fn decode_user_key_accepts_stored_hex() {
        let upper = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        assert_eq!(decode_user_key(upper).unwrap(), test_key(32));
        assert_eq!(
            decode_user_key(&upper[..32].to_ascii_lowercase()).unwrap(),
            test_key(16)
        );
        assert_eq!(decode_user_key("ABC"), Err(DeviceError::InvalidKeyHex));
        assert_eq!(decode_user_key("ZZ"), Err(DeviceError::InvalidKeyHex));
        assert_eq!(decode_user_key("+1"), Err(DeviceError::InvalidKeyHex));
        assert_eq!(
            decode_user_key("0011"),
            Err(DeviceError::InvalidKeyLength(2))
        );
    }

    #[test]
    fn signers_digest_pinned() {
        assert_eq!(HAPP_SIGNERS.scheme, SigScheme::V2);
        assert_eq!(HAPP_SIGNERS.apk_version, HAPP_VERSION);
        assert_eq!(HAPP_SIGNERS.certs.len(), 1);
        let cert = HAPP_SIGNERS.certs[0];
        assert_eq!(cert.len(), 782);
        let digest: String = sha2::Sha256::digest(cert)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            "397e98abed03c5f263ffaf4e8a1043b2a59f538b99e75cf152fa05a7e8007d8d"
        );
    }
}
