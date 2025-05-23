use derec_crypto::secret_sharing::vss::{RecoveryError, VSSShare};
use tonic::{transport::Server, Request, Response, Status};
use tokio::sync::oneshot;
use tokio::signal;

use data_encoding::BASE32;

pub mod protos;

use derec_crypto::secret_sharing::vss::*;
use derec_crypto::secure_channel::sign::*;

use sha2::{Digest, Sha256};

use protos::derec_crypto::{
    EncryptDecryptRequest,
    EncryptDecryptResponse,
    EncryptEncryptRequest, 
    EncryptEncryptResponse,
    EncryptGenerateEncryptionKeyRequest, 
    EncryptGenerateEncryptionKeyResponse, 
    SignGenerateSigningKeyRequest,
    SignGenerateSigningKeyResponse,
    SignSignRequest,
    SignSignResponse, 
    SignVerifyRequest, 
    SignVerifyResponse, 
    VssShare,
    VssShareRequest,
    VssShareResponse,
    VssRecoverRequest,
    VssRecoverResponse,
    VssDetectErrorRequest,
    VssDetectErrorResponse,
    SiblingHash
};
use protos::derec_crypto::de_rec_cryptography_service_server::{DeRecCryptographyService, DeRecCryptographyServiceServer};
use tracing::{info,error};
use tracing_subscriber;

#[derive(Debug, Default)]
pub struct MyDeRecCryptographyService;


#[allow(non_upper_case_globals)]
const λ_bits: usize = 128;

#[allow(non_upper_case_globals)]
const λ: usize = λ_bits / 8;

#[tonic::async_trait]
impl DeRecCryptographyService for MyDeRecCryptographyService {
    async fn sign_generate_signing_key(
        &self,
        _request: Request<SignGenerateSigningKeyRequest>,
    ) -> Result<Response<SignGenerateSigningKeyResponse>, Status> {
        info!("sign_generate_signing_key I");
        // Generate signing keys
        let (public_key, private_key) = derec_crypto::secure_channel::sign::generate_signing_key();
        let response: SignGenerateSigningKeyResponse = SignGenerateSigningKeyResponse {
            public_key,
            private_key,
        };
        
        info!("sign_generate_signing_key O PK: {} SK: {}",to_b32(&response.public_key),to_b32(&response.private_key));
        Ok(Response::new(response))
    }

    
    async fn sign_sign(
        &self,
        _request: Request<SignSignRequest>,
    ) -> Result<Response<SignSignResponse>, Status> {
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        // Extract message and secret_key from SignRequest
        let message = req.message;
        let secret_key: Vec<u8> = req.secret_key;
        info!("sign_sign I M: {} SK: {}",to_b32(&message),to_b32(&secret_key));

        let signature = derec_crypto::secure_channel::sign::sign(&message, &secret_key);
        let response = SignSignResponse {
            signature: signature
        };
        info!("sign_sign O M: {} SK: {}: S: {}",to_b32(&message),to_b32(&secret_key),to_b32(&response.signature));
        Ok(Response::new(response))
    }

    async fn sign_verify(
        &self,
        _request: Request<SignVerifyRequest>,
    ) -> Result<Response<SignVerifyResponse>, Status> {
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        // Extract message and secret_key from SignRequest
        let message = req.message;
        let signature = req.signature;
        let public_key: Vec<u8> = req.public_key;
        info!("sign_verify I M: {} S: {} PK: {}", to_b32(&message), to_b32(&signature), to_b32(&public_key));

        let signed = derec_crypto::secure_channel::sign::verify(&message, &signature, &public_key);
        let response = SignVerifyResponse {
            valid: signed
        };
        info!("sign_verify O M: {} S: {} PK: {}: V: {}", to_b32(&message), to_b32(&signature), to_b32(&public_key), response.valid);
        Ok(Response::new(response))
    }

    async fn encrypt_generate_encryption_key(
        &self,
        _request: Request<EncryptGenerateEncryptionKeyRequest>,
    ) -> Result<Response<EncryptGenerateEncryptionKeyResponse>, Status> {
        info!("encrypt_generate_encryption_key I");
        // Generate signing keys
        let (public_key, private_key) = derec_crypto::secure_channel::encrypt::generate_encryption_key();
        let response = EncryptGenerateEncryptionKeyResponse {
            public_key,
            private_key,
        };
        info!("encrypt_generate_encryption_key O PK: {} SK: {}",to_b32(&response.public_key),to_b32(&response.private_key));
        Ok(Response::new(response))
    }

    async fn encrypt_encrypt(
        &self,
        _request: Request<EncryptEncryptRequest>,
    ) -> Result<Response<EncryptEncryptResponse>, Status> {
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        // Extract message and secret_key from SignRequest
        let message = req.message;
        let public_key = req.public_key;
        info!("encrypt_encrypt I M: {} PK: {}",to_b32(&message),to_b32(&public_key));

        let ciphertext = derec_crypto::secure_channel::encrypt::encrypt(&message, &public_key);
        let response = EncryptEncryptResponse {
            ciphertext: ciphertext
        };
        info!("encrypt_encrypt O M: {} PK: {}: CT: {}",to_b32(&message),to_b32(&public_key),to_b32(&response.ciphertext));
        Ok(Response::new(response))
    }

    async fn encrypt_decrypt(
        &self,
        _request: Request<EncryptDecryptRequest>,
    ) -> Result<Response<EncryptDecryptResponse>, Status> {
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        // Extract message and secret_key from SignRequest
        let ciphertext = req.ciphertext;
        let secret_key = req.secret_key;
        info!("encrypt_decrypt I CT: {} SK: {}",to_b32(&ciphertext),to_b32(&secret_key));

        let message = derec_crypto::secure_channel::encrypt::decrypt(&ciphertext, &secret_key);
        let response = EncryptDecryptResponse {
            message: message
        };
        info!("encrypt_decrypt O CT: {} SK: {}: M: {}",to_b32(&ciphertext),to_b32(&secret_key),to_b32(&response.message));
        Ok(Response::new(response))
    }

    async fn vss_share(
        &self,
        _request: Request<VssShareRequest>,
    ) -> Result<Response<VssShareResponse>, Status> {
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        let t = req.t;
        let n = req.n;
        let message = req.message;
        let rand = vec_to_array_unchecked(req.rand);
        let vec = rand.to_vec();
        info!("vss_share I T: {} N: {} M: {} R: {}",t,n,to_b32(&message),to_b32(&vec));
        
        let access_structure: (u64, u64) = (t,n);

        let vss_shares = derec_crypto::secret_sharing::vss::share(access_structure, &message, &rand);
        let mut shares : Vec<VssShare> = Vec::new();
        for vss_share in vss_shares {
            let mut merkle_path: Vec<SiblingHash> = Vec::new();

            for (is_left, hash) in vss_share.merkle_path {
                let sibling_hash = SiblingHash{
                    is_left : is_left,
                    hash: hash.clone()
                };
                
                merkle_path.push(sibling_hash);
            };
            // let us create a Protobuf DerecShare struct out of stuff in vss_share
            let derec_share = VssShare{
                encrypted_secret: vss_share.encrypted_secret.clone(),
                x : vss_share.x.clone(),
                y : vss_share.y.clone(),
                commitment : vss_share.commitment.clone(),
                merkle_path: merkle_path
            };
            shares.push(derec_share);
        }

        let response = VssShareResponse{
            shares: shares
        };
        Ok(Response::new(response))
    }

    
    async fn vss_recover(
        &self,
        _request: Request<VssRecoverRequest>,
    ) -> Result<Response<VssRecoverResponse>, Status> {
        info!("vss_recover I");
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        let mut vss_shares: Vec<VSSShare> = Vec::new();
        for share in req.shares {
            let mut merkle_path : Vec<(bool, Vec<u8>)> = Vec::new();
            for path in share.merkle_path {
                merkle_path.push((
                    path.is_left,
                    path.hash
                ))
            }

            vss_shares.push(
                VSSShare { 
                    x: share.x, 
                    y: share.y, 
                    encrypted_secret: share.encrypted_secret, 
                    commitment: share.commitment, 
                    merkle_path: merkle_path
                }
            );
        }

        let result = derec_crypto::secret_sharing::vss::recover(&vss_shares);
        let mut message: Vec<u8> = Vec::new();
        let mut err:i32 = protos::derec_crypto::RecoveryErrorType::NoError as i32;

        match result
        {
            Ok(recovered) => {
                message= recovered
            },
            Err(e) => {
                err = match e {
                    RecoveryError::InconsistentCommitments => protos::derec_crypto::RecoveryErrorType::InconsistentCommitments as i32,
                    RecoveryError::InconsistentCiphertexts => protos::derec_crypto::RecoveryErrorType::InconsistentCiphertexts as i32,
                    RecoveryError::CorruptShares => protos::derec_crypto::RecoveryErrorType::CorruptShares as i32,
                    RecoveryError::InsufficientShares => protos::derec_crypto::RecoveryErrorType::InsufficientShares as i32,
                };
                
            }
        }
        let response = VssRecoverResponse{
            message: message,
            error_type: err
        };
        Ok(Response::new(response))
    }

    async fn vss_detect_error(
        &self,
        _request: Request<VssDetectErrorRequest>,
    ) -> Result<Response<VssDetectErrorResponse>, Status> {
        info!("vss_detect_error I");
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        let mut vss_shares: Vec<VSSShare> = Vec::new();
        for share in req.shares {
            let mut merkle_path : Vec<(bool, Vec<u8>)> = Vec::new();
            for path in share.merkle_path {
                merkle_path.push((
                    path.is_left,
                    path.hash
                ))
            }

            vss_shares.push(
                VSSShare { 
                    x: share.x, 
                    y: share.y, 
                    encrypted_secret: share.encrypted_secret, 
                    commitment: share.commitment, 
                    merkle_path: merkle_path
                }
            );
        }

        let result: Option<RecoveryError> = derec_crypto::secret_sharing::vss::detect_error(&vss_shares);

        let err: i32 = match result {
            Some(RecoveryError::InconsistentCommitments) => protos::derec_crypto::RecoveryErrorType::InconsistentCommitments as i32,
            Some(RecoveryError::InconsistentCiphertexts) => protos::derec_crypto::RecoveryErrorType::InconsistentCiphertexts as i32,
            Some(RecoveryError::CorruptShares) => protos::derec_crypto::RecoveryErrorType::CorruptShares as i32,
            Some(RecoveryError::InsufficientShares) => protos::derec_crypto::RecoveryErrorType::InsufficientShares as i32,
            None => protos::derec_crypto::RecoveryErrorType::NoError as i32
        };
        
        let response = VssDetectErrorResponse{
            error_type: err
        };
        Ok(Response::new(response))
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:50051".parse().unwrap();
    let service = MyDeRecCryptographyService::default();
    tracing_subscriber::fmt::init();

    info!("Server starting on {}", addr);

    // Start the tonic server

    // Create a oneshot channel for shutdown notification
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();


    // Spawn a task to listen for SIGINT and SIGTERM
    tokio::spawn(async move {

        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");

        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received SIGINT (Ctrl+C), shutting down server...");
            }
            _ = sigterm.recv()  => {
                info!("Received SIGTERM, shutting down server...");
            }
        }
        let _ = shutdown_tx.send(());
    });

    let server_future = Server::builder()
        .add_service(DeRecCryptographyServiceServer::new(service))
        .serve_with_shutdown(addr, async {
            shutdown_rx.await.ok();
        });

    match server_future.await {
        Ok(_) => info!("Server stopped gracefully."),
        Err(err) => error!("Server error: {:?}", err),
    }

    Ok(())
}

fn vec_to_array_unchecked(vec: Vec<u8>) -> [u8; λ] {
    vec.try_into().unwrap() // Panics if the vector isn't exactly 16 elements
}

fn to_b32(vec: &Vec<u8>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(vec);
    let vec_hash = hasher.finalize();
    BASE32.encode(&vec_hash).trim_end_matches('=').to_string()
}