// interfaces with derec cryptography library using 
// protobufs to encode input arguments and outputs

import java.nio.charset.StandardCharsets;

class DerecCryptoBridge {
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

    static {
        System.loadLibrary("derec_crypto_bridge_lib");
    }

    public static void main(String[] args) {

        byte[] output = DerecCryptoBridge.share(
            3, 
            5, 
            "topsecret".getBytes(), 
            "randomrandomrandom0".getBytes(),
            0,
            "some_id".getBytes()
        );

        byte[] recovered = DerecCryptoBridge.recover(output);

        System.out.println("recovered data: " + 
            new String(recovered, StandardCharsets.UTF_8));
    }
}
