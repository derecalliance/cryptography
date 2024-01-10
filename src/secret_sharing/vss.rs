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

//! Implements functions for (verifiable) secret sharing.

use anyhow::{Context, Result};

use rand_chacha::rand_core::SeedableRng;
use rand::Rng;
use serde::{Deserialize,Serialize};

use crate::secret_sharing::*;

use super::utils::compute_sha256_hash;

const MERKLE_TREE_DEPTH: u32 = 7;

/// components of a secret share in ADSS;
#[derive(Clone, Serialize, Deserialize)]
pub struct VSSShare {
    /// we use the x-coordinate to uniquely identify shares
    pub x: Vec<u8>,
    /// we use the y-coordinate as the share
    pub y: Vec<u8>,
    /// AES encryption of the secret message
    pub encrypted_secret: Vec<u8>,
    /// Merkle-root commitment to all shares
    pub commitment: Vec<u8>,
    /// bottom-up Merkle authentication path
    /// bool denotes isLeft, while vec<u8> is the SHA-384 hash
    pub merkle_path: Vec<(bool, Vec<u8>)>
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

// produces shares of an arbitrary length secret
pub fn share(
    access_structure: (u64, u64), 
    msg: &[u8], 
    rand: &[u8; λ], 
) -> Vec<VSSShare> {
    //pseudo-random key derivation
    let hash = utils::random_oracle(msg, rand, &[]);
    let k: [u8; λ] = hash[..1 * λ].try_into().unwrap();
    let seed1: [u8; 2*λ] = hash[1 * λ..3 * λ].try_into().unwrap();
    let seed2: [u8; 2*λ] = hash[3 * λ..5 * λ].try_into().unwrap();

    //AES encrypt the message using the pseudo-random key k
    let c = utils::encrypt_message(msg, &k); 

    // Shamir sharing needs randomness
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed1);

    // generate shares of the AES key k
    let shamir_shares = shamir::share(
        &k, 
        access_structure, 
        &mut rng
    );

    let merkle_tree = build_merkle_tree(
        &shamir_shares,
        MERKLE_TREE_DEPTH,
        seed2
    );
    let merkle_proofs = extract_merkle_proofs(
        &merkle_tree,
        MERKLE_TREE_DEPTH,
        access_structure.1
    );
    
    let mut output = vec![];
    for (i, (x, y)) in shamir_shares.iter().enumerate() {
        output.push(VSSShare {
            x: x.to_owned(), 
            y: y.to_owned(), 
            encrypted_secret: c.clone(), 
            commitment: merkle_tree[0].clone(), 
            merkle_path: merkle_proofs[i].to_owned()
        });
    }
    output
}

// reconstructs a secret from shares
pub fn recover(shares: &Vec<VSSShare>) -> Option<Vec<u8>> {
    assert!(shares.len() > 0);
    let c = shares[0].encrypted_secret.clone();

    let shamir_shares = shares
        .iter()
        .map(|s| (s.x.clone(), s.y.clone()))
        .collect();

    if !verify_shares(shares) {
        None
    } else {
        let k = shamir::recover(shamir_shares);
        let msg = utils::decrypt_message(&c, &k);
    
        Some(msg)
    }
}

// this function check that all shares have the same 
// commitment (and same encrypted_secret),
// and validate with respect to that commitment
pub fn verify_shares(shares: &Vec<VSSShare>) -> bool {

    let commitment = &shares[0].commitment;
    let encrypted_secret = &shares[0].encrypted_secret;

    for share in shares {
        // first check if this share has the same committment 
        // or ciphertext as all other shares
        if &share.commitment != commitment ||
            &share.encrypted_secret != encrypted_secret {
                return false;
        }

        // now verify the Merkle path

        // first compute hash of this share
        let mut on_path_hash = leaf_hash((&share.x, &share.y));

        for (is_left, node_hash) in share.merkle_path.iter() {
            on_path_hash = if *is_left {
                //sibling is on the left
                intermediate_hash(&node_hash, &on_path_hash)
            } else {
                intermediate_hash(&on_path_hash, &node_hash)
            }
        }
        
        //on_path_hash should equal the merkle root
        if &on_path_hash != commitment {
            return false;
        }
    }

    true
}

// builds a 2-ary merkle tree over shares
// we will specify a depth of the tree, even though
// we may not have that many shares. This is to 
// avoid leaking the number of shares to the attacker.
fn build_merkle_tree(shares: &[(Vec<u8>, Vec<u8>)], 
    depth: u32, 
    seed: [u8; 2*λ]
) -> Vec<Vec<u8>> {
    // let us instantiate a pseudo-random number generator
    // we will use rand to derive the seed, making everything
    // deterministic to that argument (and the input shares)
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    // merkle tree nodes are of type Vec<u8>, 
    // though we know their size to be 256 B
    let merkle_tree_size = ((2 as u32).pow(depth + 1) - 1) as usize;
    let mut merkle_nodes: Vec<Vec<u8>> = Vec::new();
    //allocate space up front
    merkle_nodes.resize(merkle_tree_size, Vec::new());

    // let us compute the leaf nodes first
    // note that we want a complete binary tree, 
    // so we pad with dummy (garbage) elements
    let num_leaf_nodes = (2 as u32).pow(depth) as usize;
    for i in 0..num_leaf_nodes {
        // root node is labelled 1; so, node labels go from 1 to 2^(depth + 1) - 1
        let node_label = num_leaf_nodes + i;
        if i < shares.len() {
            // hash the share's (x,y); node root's label starts at 1
            merkle_nodes[node_label - 1] = leaf_hash((&shares[i].0, &shares[i].1));
        } else {
            // generate a garbage values for non-existent leaf nodes
            let mut rand = [0u8; 32];
            rng.fill(&mut rand);

            merkle_nodes[node_label - 1] = rand.to_vec();
        }
    }

    //let us now compute the intermediate nodes of the merkle tree
    for height in (0..depth).rev() { //from depth - 1 down to 0
        let lo = (2 as u32).pow(height) as usize;
        let hi = ((2 as u32).pow(height + 1) - 1) as usize;

        for node_label in lo..(hi+1) { // from lo to hi
            let left_child_label = node_label * 2;
            let right_child_label = left_child_label + 1;

            //hash (left_child || right_child)
            merkle_nodes[node_label - 1] = intermediate_hash(
                &merkle_nodes[left_child_label - 1], 
                &merkle_nodes[right_child_label - 1]
            );
        }
    }

    merkle_nodes

}

// extract merkle proofs for first n leaves in a merkle tree of input depth
fn extract_merkle_proofs(
    tree: &Vec<Vec<u8>>,
    depth: u32, 
    n: u64
) -> Vec<Vec<(bool, Vec<u8>)>> {
    assert!((tree.len() + 1) > 2 && 
        ((tree.len() + 1) & (tree.len())) == 0, 
        "merkle tree not a complete binary tree");

    // even nodes' siblings are odd nodes, and vice versa
    let other_label = |x: usize| -> usize {
        if x % 2 == 0 { x + 1 } else { x - 1 }
    };
    let is_left = |x: usize| -> bool {
        if x % 2 == 0 { true } else { false }
    };

    let mut output: Vec<Vec<(bool, Vec<u8>)>> = Vec::new();

    let lo = tree.len() / 2 + 1; //label of lo node (e.g. 8)
    let hi = lo + (n as usize) - 1; // label of lo node (e.g. 15 if n = 8)

    // rust ranges are exclusive on the hi end
    for label in lo..(hi+1) {
        // the merkle path should have depth number of nodes
        let mut current_label = label;
        let mut merkle_path: Vec<(bool, Vec<u8>)> = Vec::new();
        
        for _ in 0..depth {
            let sibling_label = other_label(current_label);
            merkle_path.push((
                is_left(sibling_label),
                tree[sibling_label - 1].clone()
            ));
            current_label = current_label / 2;
        }

        output.push(merkle_path);
    }

    output
}

// A share's hash is SHA256(x || y).
fn leaf_hash(share: (&Vec<u8>, &Vec<u8>)) -> Vec<u8> {
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(&share.0);
    hasher_input.extend_from_slice(&share.1);

    compute_sha256_hash(&hasher_input)
}

fn intermediate_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(left);
    hasher_input.extend_from_slice(right);

    compute_sha256_hash(&hasher_input)
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

        assert_eq!(msg, recovered.unwrap()[..]);
    }

    #[test]
    fn test_merkle_tree_correctness() {
        let mut rng = thread_rng();

        let mut seed1 = [0u8; 16];
        rng.fill(&mut seed1);

        let mut seed2 = [0u8; 32];
        rng.fill(&mut seed2);

        let mut msg: [u8; 1024] = [0u8; 1024];
        rng.fill(&mut msg);

        let shares = share((5,7), &msg, &seed1);
        let share_points: Vec<(Vec<u8>, Vec<u8>)> = shares
            .iter()
            .map(|s| (s.x.clone(), s.y.clone()))
            .collect();
        let merkle_tree = build_merkle_tree(&share_points, 3, seed2);
        assert_merkle_tree_wff(&merkle_tree);
    }

    fn assert_merkle_tree_wff(tree: &Vec<Vec<u8>>) {
        let n = tree.len() + 1; // n must be a power of 2
        assert!(n > 2 && (n & (n - 1)) == 0, 
            "merkle tree not a complete binary tree");
        let mut hi = n / 2 - 1; //label of hi node (e.g. 7)
        let mut lo = (hi + 1) / 2; // label of lo node (e.g. 4)

        loop {
            for node_label in lo..(hi+1) {
                //we subtract 1 because root nodes are labelled 1 onwards
                let left_idx = node_label * 2 - 1;
                let right_idx = left_idx + 1;
                let expected_hash = intermediate_hash(
                    &tree[left_idx], 
                    &tree[right_idx]
                );

                assert_eq!(&expected_hash, &tree[node_label - 1]);
            }

            //set the new lo and hi
            lo = lo / 2;
            hi = hi / 2;

            if lo == hi { return; } // we got to the root node
        }
    }

}
