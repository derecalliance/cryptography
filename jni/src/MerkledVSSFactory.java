package src;

import java.security.SecureRandom;

import src.ShamirInterfaces.*;

public class MerkledVSSFactory implements SplitterFactory {
    public Splitter newSplitter(SecureRandom random, int count, int threshold) {
        byte[] entropy = new byte[16];
        random.nextBytes(entropy);

        return new MerkledVSS(entropy, count, threshold);
    }
}
