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


use rand_chacha::rand_core::OsRng;
use libsecp256k1::{PublicKey, SecretKey, Message, Signature};
use sha2::{Sha256, Digest};
use pem::{Pem, parse, encode};

fn hash_message_to_byte_array(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
    result.as_slice().try_into().unwrap()
}

// outputs the pair (pub key, secret key), 
// both in PEM encoding (as a utf-8 byte array)
pub fn generate_signing_key() -> (Vec<u8>, Vec<u8>) {
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from_secret_key(&sk);

    //let (sk, pk) = (&sk.serialize(), &pk.serialize());

    let sk_pem = Pem::new(
        "PRIVATE KEY",
        sk.serialize().to_vec()
    );

    let pk_pem = Pem::new(
        "PUBLIC KEY", 
        pk.serialize().to_vec()
    );

    (
        encode(&pk_pem).as_bytes().to_vec(),
        encode(&sk_pem).as_bytes().to_vec()
    )
}

// outputs the signature as a byte array, given a message and a secret key
// secret_key is PEM string (as a utf-8 byte array) output by generate_signing_key
pub fn sign(message: &[u8], secret_key: &[u8]) -> Vec<u8> {
    let sk_pem = parse(
        String::from_utf8(
            secret_key.to_vec()
        ).unwrap()
    ).unwrap();

    let sk_bytes: [u8; 32] = sk_pem.contents().try_into().unwrap();
    let sk = SecretKey::parse(&sk_bytes).unwrap();

    let msg = Message::parse(&hash_message_to_byte_array(message));
    let (signature, _) = libsecp256k1::sign(&msg, &sk);
    signature.serialize().to_vec()
}

// verifies a signature given a message, signature, and public key
// public_key is PEM string (as a utf-8 byte array) output by generate_signing_key
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    let pk_pem = parse(
        String::from_utf8(
            public_key.to_vec()
        ).unwrap()
    ).unwrap();

    let pk_bytes: [u8; 65] = pk_pem.contents().try_into().unwrap();
    let pk = PublicKey::parse(&pk_bytes).unwrap();
    let msg = Message::parse(&hash_message_to_byte_array(message));
    let sig = Signature::parse_standard_slice(signature).unwrap();
    libsecp256k1::verify(&msg, &sig, &pk)
}

#[cfg(test)]
mod tests {
    use super::*;    

    #[test]
    fn test_signing() {
        // Generate secret key
        let (pk, sk) = generate_signing_key();
        println!("pk: {:?}", String::from_utf8(pk.to_vec()).unwrap());
        println!("sk: {:?}", String::from_utf8(sk.to_vec()).unwrap());
        let msg = b"hello world";
        let signature = sign(msg, &sk);
        assert!(verify(msg, &signature, &pk));
    }
}
