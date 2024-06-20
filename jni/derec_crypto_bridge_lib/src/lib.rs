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

// note: adapted from the example under https://github.com/jni-rs/jni-rs

// This is the interface to the JVM that we'll
// call the majority of our methods on.
use jni::JNIEnv;

// These objects are what you should use as arguments to your native function.
// They carry extra lifetime information to prevent them escaping from the
// current local frame (which is the scope within which local (temporary)
// references to Java objects remain valid)
use jni::objects::{JClass, JByteArray};
use jni::sys::jint;

use protobuf::Message;
include!(concat!(env!("OUT_DIR"), "/bridgeproto/mod.rs"));
use bridge::{
    DerecCryptoBridgeMessage,
    DerecCryptoBridgeKeygenMessage,
};
include!(concat!(env!("OUT_DIR"), "/derecproto/mod.rs"));
use storeshare::{
    CommittedDeRecShare,
    DeRecShare,
    committed_de_rec_share::SiblingHash
};

use derec_crypto::secret_sharing::vss::*;
use derec_crypto::secure_channel::{decrypt_then_verify, encrypt::*, sign_then_encrypt};
use derec_crypto::secure_channel::sign::*;

/// error codes for recovery procedure
enum RecoveryStatus {
    Ok = 0,
    InconsistentCommitments = 1,
    InconsistentCiphertexts = 2,
    CorruptShares = 3,
    InsufficientShares = 4,
}

// This `#[no_mangle]` keeps rust from "mangling" the name and making it unique
// for this crate. The name follow a strict naming convention so that the
// JNI implementation will be able to automatically find the implementation
// of a native method based on its name.

#[no_mangle]
pub extern "system" fn Java_org_derecalliance_derec_crypto_DerecCryptoImpl_nativeShare<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    in_threshold: jint,
    in_num_shares: jint,
    in_secret: JByteArray<'local>,
    in_rand: JByteArray<'local>,
    in_version: jint,
    in_secret_id: JByteArray<'local>,
) -> JByteArray<'local> {
    // First, we have to get the byte[] out of java.
    let secret = env.convert_byte_array(&in_secret).unwrap();
    let in_rand = env.convert_byte_array(&in_rand).unwrap();
    let secret_id = env.convert_byte_array(&in_secret_id).unwrap();
    let t = in_threshold as u64;
    let n = in_num_shares as u64;

    assert!(in_rand.len() >= 16);
    let mut rand = [0u8; 16];
    rand.copy_from_slice(&in_rand[..16]);

    let vss_shares = share((t,n), &secret, &rand);

    let mut out_msg = DerecCryptoBridgeMessage::new();
    for vss_share in vss_shares {
        // let us create a Protobuf DerecShare struct out of stuff in vss_share
        let mut derec_share = DeRecShare::new();
        derec_share.encryptedSecret = vss_share.encrypted_secret.clone();
        derec_share.x = vss_share.x.clone();
        derec_share.y = vss_share.y.clone();
        derec_share.secretId = secret_id.clone();
        derec_share.version = in_version;

        let mut committed_derec_share = CommittedDeRecShare::new();
        committed_derec_share.deRecShare = derec_share.write_to_bytes().unwrap();
        committed_derec_share.commitment = vss_share.commitment.clone();

        for (is_left, hash) in vss_share.merkle_path {
            let mut sibling_hash = SiblingHash::new();
            sibling_hash.isLeft = is_left;
            sibling_hash.hash = hash.clone();

            committed_derec_share.merklePath.push(sibling_hash);
        }

        out_msg.shares.push(committed_derec_share.write_to_bytes().unwrap());
    }
    let out_bytes = out_msg.write_to_bytes().unwrap();

    // Then we have to create a new java byte[] to return.
    let output = env.byte_array_from_slice(&out_bytes).unwrap();
    output
}


#[no_mangle]
pub extern "system" fn Java_org_derecalliance_derec_crypto_DerecCryptoImpl_nativeRecover<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    in_proto_msg: JByteArray<'local>,
) -> JByteArray<'local> {
    // First, we have to get the byte[] out of java.
    let proto_msg = env.convert_byte_array(&in_proto_msg).unwrap();
    let derec_bridge_msg = DerecCryptoBridgeMessage::parse_from_bytes(&proto_msg).unwrap();

    let mut vss_shares: Vec<VSSShare> = vec![];
    for committed_derec_share_bytes in derec_bridge_msg.shares {
        let committed_derec_share = CommittedDeRecShare::parse_from_bytes(&committed_derec_share_bytes).unwrap();
        let derec_share = DeRecShare::parse_from_bytes(&committed_derec_share.deRecShare).unwrap();

        let mut merkle_path = vec![];
        for sibling_hash in committed_derec_share.merklePath {
            merkle_path.push((sibling_hash.isLeft, sibling_hash.hash));
        }

        vss_shares.push(
            VSSShare { 
                x: derec_share.x, 
                y: derec_share.y, 
                encrypted_secret: derec_share.encryptedSecret, 
                commitment: committed_derec_share.commitment, 
                merkle_path: merkle_path
            }
        );
    }

    match recover(&vss_shares)
    {
        Ok(recovered) => {
            let mut output: Vec<u8> = vec![0u8; recovered.len() + 1];
            output[0] = RecoveryStatus::Ok as u8;
            output[1..].copy_from_slice(&recovered[..]);
            // Then we have to create a new java byte[] to return.
            return env.byte_array_from_slice(&output).unwrap();
        },
        Err(e) => {
            let mut output: Vec<u8> = vec![0u8; 1];
            output[0] = match e {
                RecoveryError::InconsistentCommitments => RecoveryStatus::InconsistentCommitments as u8,
                RecoveryError::InconsistentCiphertexts => RecoveryStatus::InconsistentCiphertexts as u8,
                RecoveryError::CorruptShares => RecoveryStatus::CorruptShares as u8,
                RecoveryError::InsufficientShares => RecoveryStatus::InsufficientShares as u8,
            };
            return env.byte_array_from_slice(&output).unwrap();
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_derecalliance_derec_crypto_DerecCryptoImpl_nativeEncKeyGen<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
) -> JByteArray<'local> {

    let (pk,sk) = generate_encryption_key();

    let mut keygen_bridge_msg = DerecCryptoBridgeKeygenMessage::new();
    keygen_bridge_msg.pubkey = pk.to_owned();
    keygen_bridge_msg.privkey = sk.to_owned();

    let out_bytes = keygen_bridge_msg.write_to_bytes().unwrap();

    // Then we have to create a new java byte[] to return.
    env.byte_array_from_slice(&out_bytes).unwrap()
}

#[no_mangle]
pub extern "system" fn Java_org_derecalliance_derec_crypto_DerecCryptoImpl_nativeSignKeyGen<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
) -> JByteArray<'local> {

    let (vk, sk) = generate_signing_key();

    let mut keygen_bridge_msg = DerecCryptoBridgeKeygenMessage::new();
    keygen_bridge_msg.pubkey = vk.to_owned();
    keygen_bridge_msg.privkey = sk.to_owned();

    let out_bytes = keygen_bridge_msg.write_to_bytes().unwrap();

    // Then we have to create a new java byte[] to return.
    env.byte_array_from_slice(&out_bytes).unwrap()
}

#[no_mangle]
pub extern "system" fn Java_org_derecalliance_derec_crypto_DerecCryptoImpl_nativeSignThenEncrypt<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    in_plaintext: JByteArray<'local>,
    in_sign_privkey: JByteArray<'local>,
    in_enc_pubkey: JByteArray<'local>,
) -> JByteArray<'local> {

    let plaintext = env.convert_byte_array(&in_plaintext).unwrap();
    let sign_privkey = env.convert_byte_array(&in_sign_privkey).unwrap();
    let enc_pubkey = env.convert_byte_array(&in_enc_pubkey).unwrap();

    let ciphertext = sign_then_encrypt(
        &plaintext,
        &sign_privkey,
        &enc_pubkey
    );

    env.byte_array_from_slice(&ciphertext).unwrap()
}

#[no_mangle]
pub extern "system" fn Java_org_derecalliance_derec_crypto_DerecCryptoImpl_nativeDecryptThenVerify<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    in_ciphertext: JByteArray<'local>,
    in_sign_verifkey: JByteArray<'local>,
    in_enc_privkey: JByteArray<'local>,
) -> JByteArray<'local> {

    let ciphertext = env.convert_byte_array(&in_ciphertext).unwrap();
    let sign_verifkey = env.convert_byte_array(&in_sign_verifkey).unwrap();
    let enc_privkey = env.convert_byte_array(&in_enc_privkey).unwrap();

    let plaintext = decrypt_then_verify(
        &ciphertext,
        &sign_verifkey,
        &enc_privkey
    ).unwrap();

    env.byte_array_from_slice(&plaintext).unwrap()
}
