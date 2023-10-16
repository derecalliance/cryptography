//! Implements functions for (authenticated) secret sharing.

use anyhow::{Context, Result};
use aes::{Aes128, Block};
use aes::cipher::{
    typenum::*,
    KeyInit, 
    BlockEncryptMut,
    generic_array::GenericArray
};
use sha2::{Sha256, Digest};
use rand_chacha::rand_core::SeedableRng;
use serde::{Deserialize,Serialize};

use aes_gcm::{
    aead::Aead,
    Aes128Gcm, Nonce, Key
};

use crate::secret_sharing::*;

/// components of a secret share in ADSS;
/// derived from Fig 8 of https://eprint.iacr.org/2020/800.pdf
#[derive(Clone, Serialize, Deserialize)]
pub struct ADSSShare {
    /// unique id for the share (between 1 and n)
    share_id: u64,
    /// (t,n) access structure description
    threshold_as: (u64, u64),
    /// serialized element of finite field
    sec: Vec<u8>,
    /// AES encryption of the secret message
    pub_c: Vec<u8>,
    /// OTP-encryption of the secret randomness
    pub_d: Vec<u8>, // ideally [u8; SEC_PARAM_BYTES], but serde doesnt support
    /// commitment to the secret
    pub_j: Vec<u8>, // similarly, this is ideally [u8; 2 * SEC_PARAM_BYTES],
    /// authenticated data
    tag: Vec<u8>
}

/// implements constructor for ADSSShare 
impl ADSSShare {
    /// parses a contact structure from json
    pub fn from_str(s: &str) -> Result<Self> {
        let share: ADSSShare = serde_json::from_str(s)
            .with_context(|| format!("Failed to decode JSON from {}", s))?;
        Ok(share)
    }
}

pub fn recover(shares: Vec<ADSSShare>) -> Vec<u8> {
    assert!(shares.len() > 0);
    let access = shares[0].threshold_as.clone();
    let j = shares[0].pub_j.clone();
    let c = shares[0].pub_c.clone();
    let d: [u8; 16] = shares[0].pub_d.clone().try_into().unwrap();
    let tag = shares[0].tag.clone();

    let shamir_shares = shares
        .iter()
        .map(|s| (s.share_id, s.sec.clone()))
        .collect();

    let k = shamir::recover(access, shamir_shares);
    
    let rand = one_time_pad_rand(&d, &k);
    let msg = decrypt_message(&c, &k);

    //let's perform some checks
    let hash = random_oracle(&msg, &rand, &tag);
    assert_eq!(j, hash[0..2 * λ]);
    assert_eq!(k, hash[2 * λ..3 * λ]);

    msg
}

/// the implementation below follows Fig 8 in https://eprint.iacr.org/2020/800.pdf
pub fn share(
    access_structure: (u64, u64), 
    msg: &[u8], 
    rand: &[u8; λ], 
    tag: &[u8]
) -> Vec<ADSSShare> {
    let hash = random_oracle(msg, rand, tag);

    let j: [u8; 2*λ] = hash[0..2 * λ].try_into().unwrap();
    let k: [u8; λ] = hash[2 * λ..3 * λ].try_into().unwrap();
    let l: [u8; λ] = hash[3 * λ..4 * λ].try_into().unwrap();

    let d = one_time_pad_rand(rand, &k);
    let c = encrypt_message(msg, &k); 

    let seed = prg_seed_expansion(&l).unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let shamir_shares = shamir::share(
        &k, 
        access_structure, 
        &mut rng
    );
    
    let mut output = vec![];
    for (share_id, share_bytes) in shamir_shares {
        output.push(ADSSShare {
            share_id: share_id, 
            threshold_as: access_structure, 
            sec: share_bytes, 
            pub_c: c.clone(), 
            pub_d: d.clone(), 
            pub_j: j.to_vec(), 
            tag: tag.to_vec() 
        });
    }
    output
}

//produces 4λ bits, where λ = 128
fn random_oracle(msg: &[u8], rand: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut output : Vec<u8> = Vec::new();

    for i in 0..2 {
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

fn prg_seed_expansion(rand: &[u8]) -> Option<[u8; 32]> {
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

fn one_time_pad_rand(
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

fn encrypt_message(msg: &[u8], key: &[u8; λ]) -> Vec<u8> {
    let key: &Key<Aes128Gcm> = key.into();
    let cipher = Aes128Gcm::new(&key);
    let nonce = Nonce::<U12>::default();

    cipher.encrypt(&nonce, msg).unwrap()
}

fn decrypt_message(ctxt: &[u8], key: &[u8; λ]) -> Vec<u8> {
    let key: &Key<Aes128Gcm> = key.into();
    let cipher = Aes128Gcm::new(&key);
    let nonce = Nonce::<U12>::default();

    cipher.decrypt(&nonce, ctxt).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, thread_rng};

    #[test]
    fn test_adss_correctness() {
        // test if recovery on shares produces the shared secret

        //let seed: [u8; 32] = [0; 32];
        let mut rng = thread_rng();

        let mut rand = [0u8; 16];
        rng.fill(&mut rand);

        let mut msg: [u8; 1024] = [0u8; 1024];
        rng.fill(&mut msg);

        let shares = share((3,5), &msg, &rand, &msg);
        let recovered = recover(shares);

        assert_eq!(msg, recovered[..]);
    }
}
