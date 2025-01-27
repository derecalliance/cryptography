use kem::{Decapsulate, Encapsulate};
use ml_kem::array::ArrayN;
use ml_kem::{kem, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand_core::CryptoRngCore;

type MlKem768DecapsulationKey = kem::DecapsulationKey<MlKem768Params>;
type MlKem768EncapsulationKey = kem::EncapsulationKey<MlKem768Params>;

/// Size in bytes of the `EncapsulationKey`.
pub const ENCAPSULATION_KEY_SIZE: usize = 1184;
/// Size in bytes of the `DecapsulationKey`.
pub const DECAPSULATION_KEY_SIZE: usize = 2400;
/// Size in bytes of the `Ciphertext`.
pub const CIPHERTEXT_SIZE: usize = 1088;

/// Shared secret key.
pub type SharedSecret = [u8; 32];

/// outputs encoded decapsulation key and encoded encapsulation key
pub fn generate_encapsulation_key<R: CryptoRngCore>(rng: &mut R) -> (Vec<u8>, Vec<u8>) {
    // Generate a (decapsulation key, encapsulation key) pair
    let (dk, ek) = MlKem768::generate(rng);
    let ek_bytes = ek.as_bytes();
    let dk_bytes = dk.as_bytes();
    (dk_bytes.to_vec(), ek_bytes.to_vec())
}

/// outputs encoded ciphertext and encoded shared secret
pub fn encapsulate<R: CryptoRngCore>(ek_encoded: impl AsRef<[u8]>, rng: &mut R) -> (Vec<u8>, SharedSecret) {
    let ek = MlKem768EncapsulationKey::from_bytes(
        &as_array::<ENCAPSULATION_KEY_SIZE>(ek_encoded).unwrap().into()
    );

    let (ct, k_send) = ek.encapsulate(rng).unwrap();

    (ct.0.to_vec(), k_send.0)
}

/// outputs encoded shared secret
pub fn decapsulate(dk_encoded: impl AsRef<[u8]>, ctxt: impl AsRef<[u8]>) -> SharedSecret {
    let dk = MlKem768DecapsulationKey::from_bytes(
        &as_array::<DECAPSULATION_KEY_SIZE>(dk_encoded).unwrap().into()
    );

    let k_recv = dk.decapsulate(
        &ArrayN::<u8, CIPHERTEXT_SIZE>::try_from(ctxt.as_ref()).unwrap()
    ).unwrap();

    k_recv.0
}

pub fn as_array<const N: usize>(input: impl AsRef<[u8]>) -> Option<[u8; N]> {
    if input.as_ref().len() != N {
        return None;
    } else {
        let mut array = [0u8; N];
        array.copy_from_slice(input.as_ref());
        Some(array)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encap_decap() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = generate_encapsulation_key(&mut rng);
        let (ct, k_send) = encapsulate(&ek, &mut rng);
        let k_recv = decapsulate(&dk, &ct);
        assert_eq!(k_send, k_recv);
    }
}