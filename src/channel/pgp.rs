/*
 * Copyright (c) DeRec Alliance and its Contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! OpenPGP helper module using [rPGP facilities](https://github.com/rpgp/rpgp)

use std::collections::HashSet;
use std::io;
use std::io::Cursor;

use anyhow::{bail, format_err, Result};
use pgp::composed::{
    Deserializable, KeyType as PgpKeyType, Message, SecretKeyParamsBuilder, SignedPublicKey,
    SignedPublicSubKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::{HashAlgorithm, SymmetricKeyAlgorithm};
use pgp::types::{
    CompressionAlgorithm, KeyTrait, Mpi, PublicKeyTrait, SecretKeyTrait,
};

use smallvec::smallvec;

use rand::rngs::OsRng;
use rand_chacha::ChaChaRng;
use rand::{Rng, RngCore, SeedableRng, CryptoRng};

use crate::channel::emailaddress::EmailAddress;
use crate::channel::key::{DcKey, Fingerprint, KeyGenType};
use crate::channel::keyring::Keyring;

/// A wrapper for rPGP public key types
#[derive(Debug)]
enum SignedPublicKeyOrSubkey<'a> {
    Key(&'a SignedPublicKey),
    Subkey(&'a SignedPublicSubKey),
}

impl<'a> KeyTrait for SignedPublicKeyOrSubkey<'a> {
    fn fingerprint(&self) -> Vec<u8> {
        match self {
            Self::Key(k) => k.fingerprint(),
            Self::Subkey(k) => k.fingerprint(),
        }
    }

    fn key_id(&self) -> pgp::types::KeyId {
        match self {
            Self::Key(k) => k.key_id(),
            Self::Subkey(k) => k.key_id(),
        }
    }

    fn algorithm(&self) -> pgp::crypto::PublicKeyAlgorithm {
        match self {
            Self::Key(k) => k.algorithm(),
            Self::Subkey(k) => k.algorithm(),
        }
    }
}

impl<'a> PublicKeyTrait for SignedPublicKeyOrSubkey<'a> {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &[Mpi],
    ) -> pgp::errors::Result<()> {
        match self {
            Self::Key(k) => k.verify_signature(hash, data, sig),
            Self::Subkey(k) => k.verify_signature(hash, data, sig),
        }
    }

    fn encrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        plain: &[u8],
    ) -> pgp::errors::Result<Vec<Mpi>> {
        match self {
            Self::Key(k) => k.encrypt(rng, plain),
            Self::Subkey(k) => k.encrypt(rng, plain),
        }
    }
    

    fn to_writer_old(&self, writer: &mut impl io::Write) -> pgp::errors::Result<()> {
        match self {
            Self::Key(k) => k.to_writer_old(writer),
            Self::Subkey(k) => k.to_writer_old(writer),
        }
    }
}

/// Error with generating a PGP keypair.
///
/// Most of these are likely coding errors rather than user errors
/// since all variability is hardcoded.
#[derive(Debug, thiserror::Error)]
#[error("PgpKeygenError: {message}")]
pub struct PgpKeygenError {
    message: String,
    #[source]
    cause: anyhow::Error,
}

impl PgpKeygenError {
    fn new(message: impl Into<String>, cause: impl Into<anyhow::Error>) -> Self {
        Self {
            message: message.into(),
            cause: cause.into(),
        }
    }
}

/// A PGP keypair.
///
/// This has it's own struct to be able to keep the public and secret
/// keys together as they are one unit.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeyPair {
    pub addr: EmailAddress,
    pub public: SignedPublicKey,
    pub secret: SignedSecretKey,
}

/// Create a new key pair.
#[allow(dead_code)]
pub(crate) fn create_keypair(
    addr: EmailAddress,
    keygen_type: KeyGenType,
) -> std::result::Result<KeyPair, PgpKeygenError> {
    let (secret_key_type, public_key_type) = match keygen_type {
        KeyGenType::Rsa2048 => (PgpKeyType::Rsa(2048), PgpKeyType::Rsa(2048)),
        KeyGenType::Ed25519 | KeyGenType::Default => (PgpKeyType::EdDSA, PgpKeyType::ECDH),
    };

    let user_id = format!("<{}>", addr);
    let key_params = SecretKeyParamsBuilder::default()
        .key_type(secret_key_type)
        .can_create_certificates(true)
        .can_sign(true)
        .primary_user_id(user_id)
        .passphrase(None)
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::SHA2_256,
            HashAlgorithm::SHA2_384,
            HashAlgorithm::SHA2_512,
            HashAlgorithm::SHA2_224,
            HashAlgorithm::SHA1,
        ])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::ZIP,
        ])
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(public_key_type)
                .can_encrypt(true)
                .passphrase(None)
                .build()
                .unwrap(),
        )
        .build()
        .map_err(|err| PgpKeygenError::new("invalid key params", format_err!(err)))?;
    let key = key_params
        .generate()
        .map_err(|err| PgpKeygenError::new("invalid params", err))?;
    let private_key = key.sign(|| "".into()).expect("failed to sign secret key");

    let public_key = private_key.public_key();
    let public_key = public_key
        .sign(&private_key, || "".into())
        .map_err(|err| PgpKeygenError::new("failed to sign public key", err))?;

    private_key
        .verify()
        .map_err(|err| PgpKeygenError::new("invalid private key generated", err))?;
    public_key
        .verify()
        .map_err(|err| PgpKeygenError::new("invalid public key generated", err))?;

    Ok(KeyPair {
        addr,
        public: public_key,
        secret: private_key,
    })
}

/// Select public key or subkey to use for encryption.
///
/// First, tries to use subkeys. If none of the subkeys are suitable
/// for encryption, tries to use primary key. Returns `None` if the public
/// key cannot be used for encryption.
///
/// TODO: take key flags and expiration dates into account
fn select_pk_for_encryption(key: &SignedPublicKey) -> Option<SignedPublicKeyOrSubkey> {
    key.public_subkeys
        .iter()
        .find(|subkey| subkey.is_encryption_key())
        .map_or_else(
            || {
                // No usable subkey found, try primary key
                if key.is_encryption_key() {
                    Some(SignedPublicKeyOrSubkey::Key(key))
                } else {
                    None
                }
            },
            |subkey| Some(SignedPublicKeyOrSubkey::Subkey(subkey)),
        )
}

/// Encrypts `plain` text using `public_keys_for_encryption`
/// and signs it using `private_key_for_signing`.
pub fn pk_encrypt(
    plain: &[u8],
    public_keys_for_encryption: Keyring<SignedPublicKey>,
    private_key_for_signing: Option<SignedSecretKey>,
) -> Result<String> {
    let lit_msg = Message::new_literal_bytes("", plain);

    let pkeys: Vec<SignedPublicKeyOrSubkey> = public_keys_for_encryption
        .keys()
        .iter()
        .filter_map(|key| select_pk_for_encryption(key))
        .collect();
    let pkeys_refs: Vec<&SignedPublicKeyOrSubkey> = pkeys.iter().collect();

    //let mut rng = thread_rng();
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut rng = ChaChaRng::from_seed(seed);
    //let mut rng = new_crng();

    // TODO: measure time
    let encrypted_msg = if let Some(ref skey) = private_key_for_signing {
        lit_msg
            .sign(skey, || "".into(), Default::default())
            .and_then(|msg| msg.compress(CompressionAlgorithm::ZLIB))
            .and_then(|msg| msg.encrypt_to_keys(&mut rng, Default::default(), &pkeys_refs))
    } else {
        lit_msg.encrypt_to_keys(&mut rng, Default::default(), &pkeys_refs)
    };

    let msg = encrypted_msg?;
    let encoded_msg = msg.to_armored_string(None)?;

    Ok(encoded_msg)
}

/// Decrypts the message with keys from the private key keyring.
///
/// Receiver private keys are provided in
/// `private_keys_for_decryption`.
///
/// If `ret_signature_fingerprints` is not `None`, stores fingerprints
/// of all keys from the `public_keys_for_validation` keyring that
/// have valid signatures there.
#[allow(clippy::implicit_hasher)]
pub fn pk_decrypt(
    ctext: Vec<u8>,
    private_keys_for_decryption: Keyring<SignedSecretKey>,
    public_keys_for_validation: Keyring<SignedPublicKey>,
    ret_signature_fingerprints: Option<&mut HashSet<Fingerprint>>,
) -> Result<Vec<u8>> {

    let cursor = Cursor::new(ctext);
    let (msg, _) = Message::from_armor_single(cursor)?;

    let skeys: Vec<&SignedSecretKey> = private_keys_for_decryption.keys().iter().collect();

    let (decryptor, _) = msg.decrypt(|| "".into(), || "".into(), &skeys[..])?;
    let msgs = decryptor.collect::<pgp::errors::Result<Vec<_>>>()?;

    if let Some(msg) = msgs.into_iter().next() {
        // get_content() will decompress the message if needed,
        // but this avoids decompressing it again to check signatures
        let msg = msg.decompress()?;

        let content = match msg.get_content()? {
            Some(content) => content,
            None => bail!("The decrypted message is empty"),
        };

        if let Some(ret_signature_fingerprints) = ret_signature_fingerprints {
            if !public_keys_for_validation.is_empty() {
                let pkeys = public_keys_for_validation.keys();
                let mut my_fingerprints: Vec<Fingerprint> = Vec::new();
                if let signed_msg @ pgp::composed::Message::Signed { .. } = msg {
                    for pkey in pkeys {
                        if signed_msg.verify(&pkey.primary_key).is_ok() {
                            let fp = DcKey::fingerprint(pkey);
                            my_fingerprints.push(fp);
                        }
                    }
                }
                let fingerprints = my_fingerprints;

                ret_signature_fingerprints.extend(fingerprints);
            }
        }
        Ok(content)
    } else {
        bail!("No valid messages found");
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_keypair() {
        let keypair0 = create_keypair(
            EmailAddress::new("foo@bar.de").unwrap(),
            KeyGenType::Default,
        )
        .unwrap();
        let keypair1 = create_keypair(
            EmailAddress::new("two@zwo.de").unwrap(),
            KeyGenType::Default,
        )
        .unwrap();
        assert_ne!(keypair0.public, keypair1.public);
    }

    /// [Key] objects to use in tests.
    struct TestKeys {
        alice_secret: SignedSecretKey,
        alice_public: SignedPublicKey,
        bob_secret: SignedSecretKey,
        bob_public: SignedPublicKey,
    }

    impl TestKeys {
        fn new() -> TestKeys {
            let alice = create_keypair(
                EmailAddress::new("foo@bar.de").unwrap(),
                KeyGenType::Default,
            )
            .unwrap();
            let bob = create_keypair(
                EmailAddress::new("two@zwo.de").unwrap(),
                KeyGenType::Default,
            )
            .unwrap();
            TestKeys {
                alice_secret: alice.secret.clone(),
                alice_public: alice.public,
                bob_secret: bob.secret.clone(),
                bob_public: bob.public,
            }
        }
    }

    /// The original text of [CTEXT_SIGNED]
    static CLEARTEXT: &[u8] = b"This is a test";

    /// A ciphertext encrypted to Bob, signed by Alice.
    fn get_testing_ctext_signed(keys: &TestKeys) -> String {
        let mut keyring = Keyring::new();
        //keyring.add(keys.alice_public.clone());
        keyring.add(keys.bob_public.clone());
        pk_encrypt(
            CLEARTEXT, 
            keyring, 
            Some(keys.alice_secret.clone())
        ).unwrap()
    }

    /// A cyphertext encrypted to Bob, not signed.
    fn get_testing_ctext_unsigned(keys: &TestKeys) -> String {
        let mut keyring = Keyring::new();
        //keyring.add(keys.alice_public.clone());
        keyring.add(keys.bob_public.clone());
        pk_encrypt(
            CLEARTEXT, 
            keyring, 
            None
        ).unwrap()
    }

    #[test]
    fn test_encrypt_signed_sanity_check() {
        let keys = TestKeys::new();
        let ctxt = get_testing_ctext_signed(&keys);

        assert!(!ctxt.is_empty());
        assert!(ctxt.starts_with(
            "-----BEGIN PGP MESSAGE-----"
        ));
    }

    #[test]
    fn test_encrypt_unsigned_sanity_check() {
        let keys = TestKeys::new();
        let ctxt = get_testing_ctext_unsigned(&keys);

        assert!(!ctxt.is_empty());
        assert!(ctxt.starts_with(
            "-----BEGIN PGP MESSAGE-----"
        ));
    }

    #[test]
    fn test_decrypt_and_verify_signature() {
        let keys : TestKeys = TestKeys::new();

        // Check decrypting as Bob
        let mut decrypt_keyring: Keyring<SignedSecretKey> = Keyring::new();
        decrypt_keyring.add(keys.bob_secret.clone());

        let mut sig_check_keyring: Keyring<SignedPublicKey> = Keyring::new();
        sig_check_keyring.add(keys.alice_public.clone());

        let mut valid_signatures: HashSet<Fingerprint> = Default::default();

        let plain = pk_decrypt(
            get_testing_ctext_signed(&keys).as_bytes().to_vec(),
            decrypt_keyring,
            sig_check_keyring,
            Some(&mut valid_signatures),
        )
        .map_err(|err| println!("{:?}", err))
        .unwrap();

        assert_eq!(plain, CLEARTEXT);
        assert_eq!(valid_signatures.len(), 1);
    }

    #[test]
    fn test_decrypt_no_sig_check() {
        let keys : TestKeys = TestKeys::new();

        let mut keyring = Keyring::new();
        keyring.add(keys.bob_secret.clone());

        let empty_keyring = Keyring::new();

        let mut valid_signatures: HashSet<Fingerprint> = Default::default();

        let plain = pk_decrypt(
            get_testing_ctext_signed(&keys).as_bytes().to_vec(),
            keyring,
            empty_keyring,
            Some(&mut valid_signatures),
        )
        .unwrap();

        assert_eq!(plain, CLEARTEXT);
        assert_eq!(valid_signatures.len(), 0);
    }

    #[test]
    fn test_decrypt_signed_no_key() {
        let keys : TestKeys = TestKeys::new();

        // The validation does not have the public key of the signer.
        let mut decrypt_keyring = Keyring::new();
        decrypt_keyring.add(keys.bob_secret.clone());

        let mut sig_check_keyring = Keyring::new();
        sig_check_keyring.add(keys.bob_public.clone());

        let mut valid_signatures: HashSet<Fingerprint> = Default::default();

        let plain = pk_decrypt(
            get_testing_ctext_signed(&keys).as_bytes().to_vec(),
            decrypt_keyring,
            sig_check_keyring,
            Some(&mut valid_signatures),
        )
        .unwrap();

        assert_eq!(plain, CLEARTEXT);
        assert_eq!(valid_signatures.len(), 0);
    }

    #[test]
    fn test_decrypt_unsigned() {
        let keys : TestKeys = TestKeys::new();

        let mut decrypt_keyring = Keyring::new();
        decrypt_keyring.add(keys.bob_secret.clone());

        let sig_check_keyring = Keyring::new();

        let mut valid_signatures: HashSet<Fingerprint> = Default::default();

        let plain = pk_decrypt(
            get_testing_ctext_unsigned(&keys).as_bytes().to_vec(),
            decrypt_keyring,
            sig_check_keyring,
            Some(&mut valid_signatures),
        )
        .unwrap();

        assert_eq!(plain, CLEARTEXT);
        assert_eq!(valid_signatures.len(), 0);
    }

    #[test]
    fn test_decrypt_signed_no_sigret() {
        let keys : TestKeys = TestKeys::new();

        // Check decrypting signed cyphertext without providing the HashSet for signatures.
        let mut decrypt_keyring = Keyring::new();
        decrypt_keyring.add(keys.bob_secret.clone());
        
        let mut sig_check_keyring = Keyring::new();
        sig_check_keyring.add(keys.alice_public.clone());

        let plain = pk_decrypt(
            get_testing_ctext_signed(&keys).as_bytes().to_vec(),
            decrypt_keyring,
            sig_check_keyring,
            None,
        )
        .unwrap();
    
        assert_eq!(plain, CLEARTEXT);
    }
}
