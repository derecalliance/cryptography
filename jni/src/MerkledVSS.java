package src;

import src.ShamirInterfaces.*;
import derec.crypto.bridge.Bridge.*;

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
            List<CommittedDeRecShare> shares = bridgeMsg.getSharesList();
            List<byte[]> output = new ArrayList<>();
            for (CommittedDeRecShare share: shares) {
                output.add(share.toByteArray());
            }
            return output;
        } catch(Exception e) {
            return null;
        }
    }

    public byte[] combine(byte[] id, int version, List<byte[]> shares) {
        try {
            List<CommittedDeRecShare> protoShares = new ArrayList<>();
            for (byte[] share: shares) {
                protoShares.add(CommittedDeRecShare.parseFrom(share));
            }

            DerecCryptoBridgeMessage.Builder msgBuilder = DerecCryptoBridgeMessage.newBuilder();
            msgBuilder.addAllShares(protoShares);
            DerecCryptoBridgeMessage msg = msgBuilder.build();

            byte[] recovered = recover(msg.toByteArray());
            return recovered;
        } catch(Exception e) {
            return null;
        }
    }
}
