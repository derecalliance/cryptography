package org.derecalliance.derec.crypto;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import com.google.protobuf.ByteString;

import org.derecalliance.derec.bridge.Bridge.*;

public class DerecCryptoImpl implements DerecCryptoInterface {

    // load the rust implementation for the native methods
    static {
        System.loadLibrary("derec_crypto_bridge_lib");
    }

    /**************** BEGIN RUST NATIVE METHODS DECLARATION ****************/

    // declare methods that we expect the rust side of the bridge to implement
    private static native byte[] nativeShare(
        int threshold, // reconstruction threshold of secret sharing scheme
        int helperCount, // total number of shares to generate
        byte[] secret, // arbitrary length secret
        byte[] entropy, // randomness of length >= 16 bytes
        int version, // version of share
        byte[] secret_id // unique identifier for the secret
    );

    private static native byte[] nativeRecover(
        byte[] shares //protobuf encoding of DerecCryptoBridgeMessage
    );

    public native byte[] nativeEncKeyGen();

    public native byte[] nativeSignKeyGen();

    public native byte[] nativeSignThenEncrypt(
        byte[] plaintext, // arbitrary length plaintext
        byte[] sign_privkey, // private key for signing
        byte[] enc_pubkey // public key for encryption
    );

    public native byte[] nativeDecryptThenVerify(
        byte[] ciphertext, // arbitrary length ciphertext
        byte[] sign_verifkey, // public key for verification
        byte[] enc_privkey // private key for decryption
    );

    /**************** END RUST NATIVE METHODS DECLARATION ****************/

    public static final byte RECOVERY_STATUS_OK = 0;
    public static final byte RECOVERY_STATUS_INCONSISTENT_COMMITMENTS = 1;
    public static final byte RECOVERY_STATUS_INCONSISTENT_CIPHERTEXTS = 2;
    public static final byte RECOVERY_STATUS_INCONSISTENT_CORRUPT_SHARES = 3;
    public static final byte RECOVERY_STATUS_INCONSISTENT_INSUFFICIENT_SHARES = 3;

    // all native methods are deterministic, and entropy is supplied by the app
    private SecureRandom entropySource;

    /**
     * Constructor that chooses its own entropy source
     * @return instance of DerecCryptoImpl
     */
    public DerecCryptoImpl() {
        // we will use the secure random instance provided by the platform
        this.entropySource = new SecureRandom();
    }

    /**
     * Constructor that uses the provided entropy source
     * @return instance of DerecCryptoImpl
     */
    public DerecCryptoImpl(SecureRandom rand) {
        this.entropySource = rand;
    }

    public List<byte[]> share(byte[] id, int version, byte[] secret, int count, int threshold) {

        // sample some random bits
        byte[] entropy = new byte[16];
        this.entropySource.nextBytes(entropy);

        // invoke the rust-land native method
        byte[] bridgeOutput = nativeShare(threshold, count, secret, entropy, version, id);

        // let's try parsing the output and getting the shares
        try {
            DerecCryptoBridgeMessage bridgeMsg =
                DerecCryptoBridgeMessage.parseFrom(bridgeOutput);

            // we will be returning the following list of byte arrays
            List<byte[]> output = new ArrayList<>();
            for (ByteString share_bytes: bridgeMsg.getSharesList()) {
                output.add(share_bytes.toByteArray());
            }
            return output;

        } catch(Exception e) {
            System.out.println(e);
            return null; //TODO: do better error handling
        }
    }

    public byte[] recover(byte[] id, int version, List<byte[]> shares) {
        try {
            List<ByteString> protoShares = new ArrayList<>();
            for (byte[] share: shares) {
                protoShares.add(ByteString.copyFrom(share));
            }

            DerecCryptoBridgeMessage.Builder msgBuilder = DerecCryptoBridgeMessage.newBuilder();
            msgBuilder.addAllShares(protoShares);
            DerecCryptoBridgeMessage msg = msgBuilder.build();

            byte[] native_result = nativeRecover(msg.toByteArray());
            byte status = native_result[0];
            if (status == RECOVERY_STATUS_OK) {
                byte[] secret = new byte[native_result.length - 1];
                System.arraycopy(native_result, 1, secret, 0, secret.length);
                return secret;
            } else {
                throw new Exception("Recovery error: " + status);
            }
        } catch(Exception e) {
            System.out.println(e);
            return null;
        }
    }

    public Object[] encryptionKeyGen() {
        byte[] bridgeOutput = nativeEncKeyGen();

        try {
            DerecCryptoBridgeKeygenMessage bridgeMsg =
                DerecCryptoBridgeKeygenMessage.parseFrom(bridgeOutput);

            return new Object[] {
                bridgeMsg.getPubkey().toByteArray(),
                bridgeMsg.getPrivkey().toByteArray()
            };
            
        } catch(Exception e) {
            return null; //TODO: do better error handling
        }
    }

    public Object[] signatureKeyGen() {
        byte[] bridgeOutput = nativeSignKeyGen();

        try {
            DerecCryptoBridgeKeygenMessage bridgeMsg =
                DerecCryptoBridgeKeygenMessage.parseFrom(bridgeOutput);

            return new Object[] {
                bridgeMsg.getPubkey().toByteArray(),
                bridgeMsg.getPrivkey().toByteArray()
            };
            
        } catch(Exception e) {
            return null; //TODO: do better error handling
        }
    }

    public byte[] signThenEncrypt(byte[] message, byte[] signPrivKey, byte[] encPubKey) {
        return nativeSignThenEncrypt(message, signPrivKey, encPubKey);
    }

    public byte[] decryptThenVerify(byte[] ciphertext, byte[] verifPubKey, byte[] decPrivKey) {
        return nativeDecryptThenVerify(ciphertext, verifPubKey, decPrivKey);
    }
}
