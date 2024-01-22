use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    pkcs8::EncodePrivateKey,
    PublicKey, SecretKey,
};
use rand_chacha::rand_core::OsRng;

// outputs the pair (pub key, secret key), 
// both in PEM encoding (as a utf-8 byte array)
pub fn generate_signing_key() -> (Vec<u8>, Vec<u8>) {
    // Generate secret key
    let secret_key = SecretKey::random(&mut OsRng);

    // serialize secret key in PEM format
    let secret_key_serialized = secret_key
        .to_pkcs8_pem(Default::default())
        .unwrap()
        .to_string();

    // Derive public key from secret key
    let public_key = secret_key.public_key();

    // serializing public key in PEM format
    let public_key_serialized = public_key.to_string();
    
    // output the pair (pub key, secret key)
    (
        public_key_serialized.as_bytes().to_vec(), 
        secret_key_serialized.as_bytes().to_vec()
    )
}

// outputs the signature as a byte array, given a message and a secret key
// secret_key is PEM string (as a utf-8 byte array) output by generate_signing_key
pub fn sign(message: &[u8], secret_key: &[u8]) -> Vec<u8> {

    // parse secret key from PEM format
    let secret_key = String::from_utf8(secret_key.to_vec())
        .unwrap()
        .parse::<SecretKey>()
        .unwrap();

    // convert secret key to signing key
    let signing_key: SigningKey = secret_key.into();

    // let us sign
    let signature: Signature = signing_key.sign(message);
    signature.to_vec()
}

// verifies a signature given a message, signature, and public key
// public_key is PEM string (as a utf-8 byte array) output by generate_signing_key
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    // Load public key
    let public_key = String::from_utf8(public_key.to_vec())
        .unwrap()
        .parse::<PublicKey>()
        .unwrap();

    // convert public key to verifying key
    let verifying_key: VerifyingKey = public_key.into();

    // parse signature in byte array
    let signature = Signature::try_from(&signature[..]).unwrap();

    // output boolean indicating whether signature is valid
    verifying_key.verify(message, &signature).is_ok()
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