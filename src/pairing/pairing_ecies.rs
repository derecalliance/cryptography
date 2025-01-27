use ark_ec::*;
use ark_ff::*;
use rand::Rng;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use sha2::*;

pub fn generate_key<R: Rng>(rng: &mut R) -> (Vec<u8>, Vec<u8>) {
    let sk = ark_secp256k1::Fr::rand(rng);
    let pk = ark_secp256k1::Affine::generator() * sk;

    let mut sk_bytes = Vec::new();
    sk.serialize_uncompressed(&mut sk_bytes).unwrap();

    let mut pk_bytes = Vec::new();
    pk.serialize_uncompressed(&mut pk_bytes).unwrap();

    (sk_bytes, pk_bytes)
}

pub fn derive_shared_key(sk: &[u8], pk: &[u8]) -> [u8; 32] {
    let sk = ark_secp256k1::Fr::deserialize_uncompressed(sk).unwrap();
    let pk = ark_secp256k1::Affine::deserialize_uncompressed(pk).unwrap();

    let shared_key = pk * sk;

    let mut shared_key_bytes = Vec::new();
    shared_key.serialize_uncompressed(&mut shared_key_bytes).unwrap();

    let mut hasher = sha2::Sha256::new();
    hasher.update(shared_key_bytes);
    hasher.finalize().into()
}