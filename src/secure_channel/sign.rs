use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    pkcs8::EncodePrivateKey,
    PublicKey, SecretKey,
};
use rand_chacha::rand_core::OsRng;

// outputs the pair (pub key, priv key)
pub fn generate_signing_key() -> (Vec<u8>, Vec<u8>) {
    // Generate secret key
    let secret_key = SecretKey::random(&mut OsRng);

    let secret_key_serialized = secret_key
        .to_pkcs8_pem(Default::default())
        .unwrap()
        .to_string();

    // Derive public key
    let public_key = secret_key.public_key();

    // Store public key
    let public_key_serialized = public_key.to_string();
    
    (
        public_key_serialized.as_bytes().to_vec(), 
        secret_key_serialized.as_bytes().to_vec()
    )
}

// outputs the signature as a byte array
pub fn sign_message(message: &[u8], secret_key: &[u8]) -> Vec<u8> {
    // Load secret key
    let secret_key = String::from_utf8(secret_key.to_vec())
        .unwrap()
        .parse::<SecretKey>()
        .unwrap();

    // convert secret key to signing key
    let signing_key: SigningKey = secret_key.into();

    let signature: Signature = signing_key.sign(message);

    signature.to_vec()
}

pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    // Load public key
    let public_key = String::from_utf8(public_key.to_vec())
        .unwrap()
        .parse::<PublicKey>()
        .unwrap();

    // convert public key to verifying key
    let verifying_key: VerifyingKey = public_key.into();

    let signature = Signature::try_from(&signature[..]).unwrap();

    verifying_key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;    

    #[test]
    fn test_signing() {
        // Generate secret key
        let (pk, sk) = generate_signing_key();
        let msg = b"hello world";
        let signature = sign_message(msg, &sk);
        assert!(verify_signature(msg, &signature, &pk));
    }
}