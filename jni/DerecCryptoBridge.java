// interfaces with derec cryptography library using 
// protobufs to encode input arguments and outputs
class DerecCryptoBridge {
    private static native byte[] share(
        int threshold, 
        int helperCount, 
        byte[] secret,
        byte[] entropy,
        int version,
        byte[] secret_id);

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
        System.out.println("output of len " + output.length + " and contents " + output);
    }
}
