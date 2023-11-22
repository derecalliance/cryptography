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
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
use bridge::{
    DerecCryptoBridgeMessage,
    CommittedDeRecShare,
    DeRecShare,
    committed_de_rec_share::SiblingHash
};

use derec_crypto::secret_sharing::vss::*;


// This `#[no_mangle]` keeps rust from "mangling" the name and making it unique
// for this crate. The name follow a strict naming convention so that the
// JNI implementation will be able to automatically find the implementation
// of a native method based on its name.

#[no_mangle]
pub extern "system" fn Java_src_MerkledVSS_share<'local>(
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

        out_msg.shares.push(committed_derec_share);
    }
    let out_bytes = out_msg.write_to_bytes().unwrap();

    // Then we have to create a new java byte[] to return.
    let output = env.byte_array_from_slice(&out_bytes).unwrap();
    output
}


#[no_mangle]
pub extern "system" fn Java_src_MerkledVSS_recover<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    in_proto_msg: JByteArray<'local>,
) -> JByteArray<'local> {
    // First, we have to get the byte[] out of java.
    let proto_msg = env.convert_byte_array(&in_proto_msg).unwrap();
    let derec_bridge_msg = DerecCryptoBridgeMessage::parse_from_bytes(&proto_msg).unwrap();

    let mut vss_shares: Vec<VSSShare> = vec![];
    for committed_derec_share in derec_bridge_msg.shares {
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

    let recovered = recover(&vss_shares).unwrap();

    // Then we have to create a new java byte[] to return.
    let output = env.byte_array_from_slice(&recovered).unwrap();
    output
}
