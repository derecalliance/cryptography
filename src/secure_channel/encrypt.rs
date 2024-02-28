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

use rand_chacha::rand_core::OsRng; // requires 'getrandom' feature
use pem::{Pem, parse, encode};
use libsecp256k1::{PublicKey, SecretKey};

// outputs the pair (pub key, priv key), both in PEM format
pub fn generate_encryption_key() -> (Vec<u8>, Vec<u8>) {
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

// outputs the signature as a byte array
pub fn encrypt(message: &[u8], public_key: &[u8]) -> Vec<u8> {

    let pk_pem = parse(
        String::from_utf8(
            public_key.to_vec()
        ).unwrap()
    ).unwrap();

    let pk = pk_pem.contents();

    ecies::encrypt(pk, message).unwrap()
}

pub fn decrypt(ciphertext: &[u8], secret_key: &[u8]) -> Vec<u8> {
    let sk_pem = parse(
        String::from_utf8(
            secret_key.to_vec()
        ).unwrap()
    ).unwrap();

    let sk = sk_pem.contents();
    ecies::decrypt(sk, ciphertext).unwrap()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption() {
        // Generate secret key
        let (pk, sk) = generate_encryption_key();
        // println!("pk: {:?}", String::from_utf8(pk.to_vec()).unwrap());
        // println!("sk: {:?}", String::from_utf8(sk.to_vec()).unwrap());

        let msg = b"hello world";
        let ctxt = encrypt(msg, &pk);

        assert_eq!(msg, decrypt(&ctxt, &sk).as_slice());
    }
}
