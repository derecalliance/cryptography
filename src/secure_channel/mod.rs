pub mod sign;
pub mod encrypt;

pub fn sign_then_encrypt(
    message: &[u8],
    signing_key: &[u8],
    public_key: &[u8]
) -> Vec<u8> {
    let signature = sign::sign(message, signing_key);

    // let us assemble the cleartext as signature followed by the message
    let mut cleartext = vec![];
    cleartext.extend_from_slice(&signature);
    cleartext.extend_from_slice(message);

    encrypt::encrypt(&cleartext, public_key)
}

pub fn decrypt_then_verify(
    ciphertext: &[u8],
    verification_key: &[u8],
    secret_key: &[u8]
) -> Option<Vec<u8>> {
    let cleartext = encrypt::decrypt(ciphertext, secret_key);

    // signature is first 64 bytes
    let signature = &cleartext[..64];
    // rest is the message bytes
    let message = &cleartext[64..];

    if sign::verify(&message, &signature, verification_key) {
        Some(message.to_vec())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_then_encrypt() {
        let (alice_signing_vk, alice_signing_sk) =
            sign::generate_signing_key();
        let (alice_encryption_pk, alice_encryption_sk) =
            encrypt::generate_encryption_key();

        let (bob_signing_vk, bob_signing_sk) =
            sign::generate_signing_key();
        let (bob_encryption_pk, bob_encryption_sk) =
            encrypt::generate_encryption_key();

        let msg = b"hello from alice";

        // let alice sign-then-encrypt the message for bob
        let ctxt = super::sign_then_encrypt(
            msg, &alice_signing_sk, &bob_encryption_pk
        );

        // let bob decrypt-then-verify the message from alice
        let received = super::decrypt_then_verify(
            &ctxt, &alice_signing_vk, &bob_encryption_sk
        );

        assert_eq!(received.unwrap(), msg);
    }
}