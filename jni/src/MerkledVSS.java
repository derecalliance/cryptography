package src;

import com.google.protobuf.ByteString;
import src.ShamirInterfaces.*;
import org.derecalliance.derec.bridge.Bridge.*;
import org.derecalliance.derec.protobuf.Storeshare.*;

import java.util.ArrayList;
import java.util.List;

public class MerkledVSS implements Splitter {
    static {
        System.loadLibrary("derec_crypto_bridge_lib");
    }

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

    private byte[] entropy;
    private int count, threshold;

    public MerkledVSS(byte[] entropy, int count, int threshold) {
        this.entropy = entropy;
        this.count = count;
        this.threshold = threshold;
    }

    public List<byte[]> split(byte[] id, int version, byte[] secret) {
        byte[] bridgeOutput = share(
            this.threshold, 
            this.count, 
            secret, 
            this.entropy,
            version,
            id
        );

        try {
            DerecCryptoBridgeMessage bridgeMsg = 
                DerecCryptoBridgeMessage.parseFrom(bridgeOutput);

            List<byte[]> output = new ArrayList<>();
            for (ByteString share_bytes: bridgeMsg.getSharesList()) {
                //CommittedDeRecShare share =
                //      CommittedDeRecShare.parseFrom(share_bytes.toByteArray());
                output.add(share_bytes.toByteArray());
            }
            return output;
        } catch(Exception e) {
            return null;
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
