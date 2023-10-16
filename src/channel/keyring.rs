//! Keyring to perform rpgp operations with.

use crate::channel::key::DcKey;

/// An in-memory keyring.
///
/// Instances are usually constructed just for the rpgp operation and
/// short-lived.
#[derive(Clone, Debug, Default)]
pub struct Keyring<T>
where
    T: DcKey,
{
    keys: Vec<T>,
}

#[allow(dead_code)]
impl<T> Keyring<T>
where
    T: DcKey<KeyType = T>,
{
    /// New empty keyring.
    pub fn new() -> Keyring<T> {
        Keyring { keys: Vec::new() }
    }

    /// Add a key to the keyring.
    pub fn add(&mut self, key: T) {
        self.keys.push(key);
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// A vector with reference to all the keys in the keyring.
    pub fn keys(&self) -> &[T] {
        &self.keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::key::*;
    use crate::channel::pgp::*;
    use crate::channel::emailaddress::*;

    #[test]
    fn test_keyring_add_keys() {
        let keypair = create_keypair(
            EmailAddress::new(&format!("alice@example.net")).unwrap(),
            KeyGenType::Ed25519
        ).unwrap();
        let pk = keypair.public;

        let mut pub_ring: Keyring<SignedPublicKey> = Keyring::new();
        pub_ring.add(pk.clone());
        assert_eq!(pub_ring.keys(), [pk]);
    }
}