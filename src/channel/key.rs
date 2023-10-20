//! Cryptographic key module

use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;

use base64::{Engine as _, engine::general_purpose};

use anyhow::{format_err, Result};
//use num_traits::FromPrimitive;
use pgp::composed::Deserializable;
use pgp::ser::Serialize;
use pgp::types::{KeyTrait, SecretKeyTrait};

// Re-export key types
pub use crate::channel::pgp::KeyPair;
pub use pgp::composed::{SignedPublicKey, SignedSecretKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum KeyGenType {
    Default = 0,
    Rsa2048 = 1,
    Ed25519 = 2,
}


/// Convenience trait for working with keys.
///
/// This trait is implemented for rPGP's [SignedPublicKey] and
/// [SignedSecretKey] types and makes working with them a little
/// easier in the deltachat world.
pub trait DcKey: Serialize + Deserializable + KeyTrait + Clone {
    type KeyType: Serialize + Deserializable + KeyTrait + Clone;

    /// Create a key from some bytes.
    fn from_slice(bytes: &[u8]) -> Result<Self::KeyType> {
        Ok(<Self::KeyType as Deserializable>::from_bytes(Cursor::new(
            bytes,
        ))?)
    }

    /// Create a key from a base64 string.
    fn from_base64(data: &str) -> Result<Self::KeyType> {
        // strip newlines and other whitespace
        let cleaned: String = data.trim().split_whitespace().collect();
        let bytes = general_purpose::STANDARD
            .decode(cleaned)?;
        Self::from_slice(&bytes)
    }

    /// Create a key from an ASCII-armored string.
    ///
    /// Returns the key and a map of any headers which might have been set in
    /// the ASCII-armored representation.
    fn from_asc(data: &str) -> Result<(Self::KeyType, BTreeMap<String, String>)> {
        let bytes = data.as_bytes();
        Self::KeyType::from_armor_single(Cursor::new(bytes))
            .map_err(|err| format_err!("rPGP error: {}", err))
    }

    /// Serialise the key as bytes.
    fn to_bytes(&self) -> Vec<u8> {
        // Not using Serialize::to_bytes() to make clear *why* it is
        // safe to ignore this error.
        // Because we write to a Vec<u8> the io::Write impls never
        // fail and we can hide this error.
        let mut buf = Vec::new();
        self.to_writer(&mut buf).unwrap();
        buf
    }

    /// Serialise the key to a base64 string.
    fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(&DcKey::to_bytes(self))
    }

    /// Serialise the key to ASCII-armored representation.
    ///
    /// Each header line must be terminated by `\r\n`.  Only allows setting one
    /// header as a simplification since that's the only way it's used so far.
    // Since .to_armored_string() are actual methods on SignedPublicKey and
    // SignedSecretKey we can not generically implement this.
    fn to_asc(&self, header: Option<(&str, &str)>) -> String;

    /// The fingerprint for the key.
    fn fingerprint(&self) -> Fingerprint {
        Fingerprint::new(KeyTrait::fingerprint(self)).expect("Invalid fingerprint from rpgp")
    }
}

impl DcKey for SignedPublicKey {
    type KeyType = SignedPublicKey;

    fn to_asc(&self, header: Option<(&str, &str)>) -> String {
        // Not using .to_armored_string() to make clear *why* it is
        // safe to ignore this error.
        // Because we write to a Vec<u8> the io::Write impls never
        // fail and we can hide this error.
        let headers = header.map(|(key, value)| {
            let mut m = BTreeMap::new();
            m.insert(key.to_string(), value.to_string());
            m
        });
        let mut buf = Vec::new();
        self.to_armored_writer(&mut buf, headers.as_ref())
            .unwrap_or_default();
        std::string::String::from_utf8(buf).unwrap_or_default()
    }
}

impl DcKey for SignedSecretKey {
    type KeyType = SignedSecretKey;

    fn to_asc(&self, header: Option<(&str, &str)>) -> String {
        // Not using .to_armored_string() to make clear *why* it is
        // safe to do these unwraps.
        // Because we write to a Vec<u8> the io::Write impls never
        // fail and we can hide this error.  The string is always ASCII.
        let headers = header.map(|(key, value)| {
            let mut m = BTreeMap::new();
            m.insert(key.to_string(), value.to_string());
            m
        });
        let mut buf = Vec::new();
        self.to_armored_writer(&mut buf, headers.as_ref())
            .unwrap_or_default();
        std::string::String::from_utf8(buf).unwrap_or_default()
    }
}

/// Deltachat extension trait for secret keys.
///
/// Provides some convenience wrappers only applicable to [SignedSecretKey].
pub trait DcSecretKey {
    /// Create a public key from a private one.
    fn split_public_key(&self) -> Result<SignedPublicKey>;
}

impl DcSecretKey for SignedSecretKey {
    fn split_public_key(&self) -> Result<SignedPublicKey> {
        self.verify()?;
        let unsigned_pubkey = SecretKeyTrait::public_key(self);
        let signed_pubkey = unsigned_pubkey.sign(self, || "".into())?;
        Ok(signed_pubkey)
    }
}

/// A key fingerprint
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Fingerprint(Vec<u8>);

impl Fingerprint {
    pub fn new(v: Vec<u8>) -> Result<Fingerprint> {
        match v.len() {
            20 => Ok(Fingerprint(v)),
            _ => Err(format_err!("Wrong fingerprint length")),
        }
    }

    /// Make a hex string from the fingerprint.
    ///
    /// Use [std::fmt::Display] or [ToString::to_string] to get a
    /// human-readable formatted string.
    pub fn hex(&self) -> String {
        hex::encode_upper(&self.0)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fingerprint")
            .field("hex", &self.hex())
            .finish()
    }
}

/// Make a human-readable fingerprint.
impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Split key into chunks of 4 with space and newline at 20 chars
        for (i, c) in self.hex().chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                write!(f, " ")?;
            }
            write!(f, "{}", c)?;
        }
        Ok(())
    }
}

/// Parse a human-readable or otherwise formatted fingerprint.
impl std::str::FromStr for Fingerprint {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> std::result::Result<Self, Self::Err> {
        let hex_repr: String = input
            .to_uppercase()
            .chars()
            .filter(|&c| ('0'..='9').contains(&c) || ('A'..='F').contains(&c))
            .collect();
        let v: Vec<u8> = hex::decode(hex_repr)?;
        let fp = Fingerprint::new(v)?;
        Ok(fp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::emailaddress::EmailAddress;
    use crate::channel::pgp::*;

    #[test]
    fn test_from_slice_roundtrip() {
        let keypair = create_keypair(
            EmailAddress::new(&format!("alice@example.net")).unwrap(),
            KeyGenType::Ed25519
        ).unwrap();
        let public_key = keypair.public;
        let private_key = keypair.secret;

        let binary = DcKey::to_bytes(&public_key);
        let public_key2 = SignedPublicKey::from_slice(&binary).expect("invalid public key");
        assert_eq!(public_key, public_key2);

        let binary = DcKey::to_bytes(&private_key);
        let private_key2 = SignedSecretKey::from_slice(&binary).expect("invalid private key");
        assert_eq!(private_key, private_key2);
    }

    #[test]
    fn test_from_slice_bad_data() {
        let mut bad_data: [u8; 4096] = [0; 4096];
        for (i, v) in bad_data.iter_mut().enumerate() {
            *v = (i & 0xff) as u8;
        }
        for j in 0..(4096 / 40) {
            let slice = &bad_data.get(j..j + 4096 / 2 + j).unwrap();
            assert!(SignedPublicKey::from_slice(slice).is_err());
            assert!(SignedSecretKey::from_slice(slice).is_err());
        }
    }

    #[test]
    fn test_base64_roundtrip() {
        let keypair = create_keypair(
            EmailAddress::new(&format!("alice@example.net")).unwrap(),
            KeyGenType::Ed25519
        ).unwrap();
        let pubkey_base64 = keypair.public.to_base64();
        let key2 = SignedPublicKey::from_base64(&pubkey_base64).unwrap();
        assert_eq!(keypair.public, key2);
    }

    // Convenient way to create a new key if you need one, run with
    // `cargo test key::tests::gen_key`.
    #[test]
    fn gen_key() {
        let name = "fiona";
        let keypair = create_keypair(
            EmailAddress::new(&format!("{}@example.net", name)).unwrap(),
            KeyGenType::Ed25519
        )
        .unwrap();
        std::fs::write(
            format!("/tmp/{}-public.asc", name),
            keypair.public.to_base64(),
        )
        .unwrap();
        std::fs::write(
            format!("/tmp/{}-secret.asc", name),
            keypair.secret.to_base64(),
        )
        .unwrap();
    }

    #[test]
    fn test_fingerprint_from_str() {
        let res = Fingerprint::new(vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ])
        .unwrap();

        let fp: Fingerprint = "0102030405060708090A0B0c0d0e0F1011121314".parse().unwrap();
        assert_eq!(fp, res);

        let fp: Fingerprint = "zzzz 0102 0304 0506\n0708090a0b0c0D0E0F1011121314 yyy"
            .parse()
            .unwrap();
        assert_eq!(fp, res);

        assert!("1".parse::<Fingerprint>().is_err());
    }

    #[test]
    fn test_fingerprint_hex() {
        let fp = Fingerprint::new(vec![
            1, 2, 4, 8, 16, 32, 64, 128, 255, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ])
        .unwrap();
        assert_eq!(fp.hex(), "0102040810204080FF0A0B0C0D0E0F1011121314");
    }

    #[test]
    fn test_fingerprint_to_string() {
        let fp = Fingerprint::new(vec![
            1, 2, 4, 8, 16, 32, 64, 128, 255, 1, 2, 4, 8, 16, 32, 64, 128, 255, 19, 20,
        ])
        .unwrap();
        assert_eq!(
            fp.to_string(),
            "0102 0408 1020 4080 FF01 0204 0810 2040 80FF 1314"
        );
    }
}