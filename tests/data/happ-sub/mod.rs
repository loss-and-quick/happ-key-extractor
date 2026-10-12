//! Key material: versioned body key tables and, with `builtin-url-keys`, the URL RSA keys.
//!
//! Body keys are not versioned on the wire, so the crate groups them into **generations**.
//! Generation 1 is the table found unchanged in Happ 4.3.0 through 4.7.1.
//!
//! `url-keys.json` holds the `happ://crypt*` RSA private keys, needed to decrypt vendor-issued
//! links client-side. It is `crypt5_keys.json` from
//! <https://github.com/KernelEditor/HappDecrypt> at commit
//! `8d0b97b1875446abb16a0d1b62492a404e766860`, unmodified.

mod gen1;

#[cfg(feature = "builtin-url-keys")]
pub(crate) const URL_KEYS_JSON: &str = include_str!("url-keys.json");

pub use gen1::KEYS_GEN1;

/// A table of 90 body AES keys associated with a measured generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyTable {
    /// Identifier for this generation (e.g. `"gen1-4.3.0..4.7.1"`).
    pub id: &'static str,
    /// 90 entries mapping key IDs (`"key01"`..`"key90"`) to 16-byte AES keys.
    pub entries: &'static [(&'static str, &'static [u8; 16])],
}

impl KeyTable {
    /// Look up the 16-byte AES key for a `key_id` (e.g. `"key02"`).
    pub fn get(&self, key_id: &str) -> Option<&'static [u8; 16]> {
        self.entries
            .iter()
            .find(|(id, _)| *id == key_id)
            .map(|(_, k)| *k)
    }

    /// Return an iterator over all `(key_id, key_bytes)` entries in this table.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &'static [u8; 16])> {
        self.entries.iter().copied()
    }

    /// Check if a key ID exists in this table.
    pub fn contains_key(&self, key_id: &str) -> bool {
        self.entries.iter().any(|(id, _)| *id == key_id)
    }
}

/// Key table for Generation 1 (measured across Happ 4.3.0 through 4.7.1).
pub const TABLE_GEN1_4_3_0_TO_4_7_1: KeyTable = KeyTable {
    id: "gen1-4.3.0..4.7.1",
    entries: KEYS_GEN1,
};

/// The default table used when no generation is explicitly pinned.
pub const DEFAULT_TABLE: &KeyTable = &TABLE_GEN1_4_3_0_TO_4_7_1;

/// Registered key tables ordered from newest to oldest.
pub const ALL_TABLES: &[&KeyTable] = &[&TABLE_GEN1_4_3_0_TO_4_7_1];
