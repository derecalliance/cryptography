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
