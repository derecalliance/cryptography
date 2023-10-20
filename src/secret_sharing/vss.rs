//! Implements functions for (verifiable) secret sharing.

use anyhow::{Context, Result};

use rand_chacha::rand_core::SeedableRng;
use serde::{Deserialize,Serialize};

use crate::secret_sharing::*;

/// components of a secret share in ADSS;
#[derive(Clone, Serialize, Deserialize)]
pub struct VSSShare {
    /// (t,n) access structure description
    threshold_access_structure: (u64, u64),
    /// we use the x-coordinate to uniquely identify shares
    x: Vec<u8>,
    /// we use the y-coordinate as the share
    y: Vec<u8>,
    /// AES encryption of the secret message
    encrypted_secret: Vec<u8>,
    /// Merkle-root commitment to all shares
    commitment: Vec<u8>,
    /// bottom-up Merkle authentication path
    /// bool denotes isLeft, while vec<u8> is the SHA-384 hash
    merkle_path: Vec<(bool, Vec<u8>)>
}

/// implements constructor for ADSSShare 
impl VSSShare {
    /// parses a VSS share structure from json
    pub fn from_str(s: &str) -> Result<Self> {
        let share: VSSShare = serde_json::from_str(s)
            .with_context(|| format!("Failed to decode JSON from {}", s))?;
        Ok(share)
    }
}


pub fn share(
    access_structure: (u64, u64), 
    msg: &[u8], 
    rand: &[u8; λ], 
) -> Vec<VSSShare> {
    //pseudo-random key derivation
    let hash = utils::random_oracle(msg, rand, &[]);
    let k: [u8; λ] = hash[..1 * λ].try_into().unwrap();
    let l: [u8; λ] = hash[1 * λ..2 * λ].try_into().unwrap();

    let c = utils::encrypt_message(msg, &k); 

    let seed = utils::prg_seed_expansion(&l).unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let shamir_shares = shamir::share(
        &k, 
        access_structure, 
        &mut rng
    );
    
    let mut output = vec![];
    for (x, y) in shamir_shares {
        output.push(VSSShare {
            threshold_access_structure: access_structure, 
            x: x, 
            y: y, 
            encrypted_secret: c.clone(), 
            commitment: vec![], 
            merkle_path: vec![] 
        });
    }
    output
}


pub fn recover(shares: &Vec<VSSShare>) -> Vec<u8> {
    assert!(shares.len() > 0);
    let access = shares[0].threshold_access_structure.clone();
    let c = shares[0].encrypted_secret.clone();

    let shamir_shares = shares
        .iter()
        .map(|s| (s.x.clone(), s.y.clone()))
        .collect();

    let k = shamir::recover(access, shamir_shares);
    let msg = utils::decrypt_message(&c, &k);

    msg
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, thread_rng};

    #[test]
    fn test_vss_correctness() {
        // test if recovery on shares produces the shared secret

        //let seed: [u8; 32] = [0; 32];
        let mut rng = thread_rng();

        let mut rand = [0u8; 16];
        rng.fill(&mut rand);

        let mut msg: [u8; 1024] = [0u8; 1024];
        rng.fill(&mut msg);

        let shares = share((3,5), &msg, &rand);
        let recovered = recover(&shares);

        assert_eq!(msg, recovered[..]);
    }
}
