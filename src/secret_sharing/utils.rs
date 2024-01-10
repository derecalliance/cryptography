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

use aes_gcm::{aead::Aead, Aes128Gcm, Nonce, Key};
use aes::{Aes128, Block};
use aes::cipher::{
    typenum::*,
    KeyInit, 
    BlockEncryptMut,
    generic_array::GenericArray
};
use sha2::{Sha256, Digest};
use crate::secret_sharing::*;

pub fn compute_sha256_hash(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

pub fn prg_seed_expansion(rand: &[u8]) -> Option<[u8; 32]> {
    if rand.len() != 16 { //expecting only 128 bit keys
        return None;
    }

    let mut seed : [u8; 32] = [0u8; 32];
    for i in 0..16 {
        seed[2*i] = rand[i];
        seed[2*i + 1] = rand[i];
    }
    Some(seed)
}

pub fn one_time_pad_rand(
    rand: &[u8; λ], 
    key: &[u8; λ]
) -> Vec<u8> {
    let mut cipher = Aes128::new(&GenericArray::from_slice(key));

    let mut block = Block::default();
    cipher.encrypt_block_mut(&mut block);

    let ciphertext_block : Vec<u8> = rand
            .iter()
            .zip(block.iter())
            .map(|(x1, x2)| x1 ^ x2)
            .collect();

    ciphertext_block
}

pub fn encrypt_message(msg: &[u8], key: &[u8; λ]) -> Vec<u8> {
    let key: &Key<Aes128Gcm> = key.into();
    let cipher = Aes128Gcm::new(&key);
    let nonce = Nonce::<U12>::default();

    cipher.encrypt(&nonce, msg).unwrap()
}

pub fn decrypt_message(ctxt: &[u8], key: &[u8; λ]) -> Vec<u8> {
    let key: &Key<Aes128Gcm> = key.into();
    let cipher = Aes128Gcm::new(&key);
    let nonce = Nonce::<U12>::default();

    cipher.decrypt(&nonce, ctxt).unwrap()
}

//produces 4λ bits, where λ = 128
pub fn random_oracle(msg: &[u8], rand: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut output : Vec<u8> = Vec::new();

    for i in 0..4 {
        // create a Sha256 object
        let mut hasher = Sha256::new();
        // H(msg || rand || tag)
        hasher.update(msg);
        hasher.update(rand);
        hasher.update(tag);
        hasher.update([i as u8; 1]); //counter as hash input

        // read hash digest and consume hasher
        let hash = hasher.finalize();
        for &b in hash.as_slice() {
            output.push(b);
        }
    }

    output
}
