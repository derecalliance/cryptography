package src;

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
    private static native byte[] share(
        int threshold, // reconstruction threshold of secret sharing scheme
        int helperCount, // total number of shares to generate
        byte[] secret, // arbitrary length secret
        byte[] entropy, // randomness of length >= 16 bytes
        int version, // version of share
        byte[] secret_id // unique identifier for the secret
    );

    private static native byte[] recover(
        byte[] shares //protobuf encoding of DerecCryptoBridgeMessage
    );

    /**************** END RUST NATIVE METHODS DECLARATION ****************/

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

    public List<byte[]> split(byte[] id, int version, byte[] secret, int count, int threshold) {

        // sample some random bits
        byte[] entropy = new byte[16];
        this.entropySource.nextBytes(entropy);

        // invoke the rust-land native method
        byte[] bridgeOutput = share(threshold, count, secret, entropy, version, id);

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
            return null; //TODO: do better error handling
        }
    }

    public byte[] combine(byte[] id, int version, List<byte[]> shares) {
        try {
            List<ByteString> protoShares = new ArrayList<>();
            for (byte[] share: shares) {
                protoShares.add(ByteString.copyFrom(share));
            }

            DerecCryptoBridgeMessage.Builder msgBuilder = DerecCryptoBridgeMessage.newBuilder();
            msgBuilder.addAllShares(protoShares);
            DerecCryptoBridgeMessage msg = msgBuilder.build();

            return recover(msg.toByteArray());
        } catch(Exception e) {
            return null;
        }
    }
}
