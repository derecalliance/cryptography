package src;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;

import src.ShamirInterfaces.Splitter;

public class DerecCryptoBridgeTestMain {
    public static void main(String[] args) {
        SecureRandom random = new SecureRandom("FIXMENOW".getBytes());
        Splitter splitter = new MerkledVSSFactory().newSplitter(random, 5, 3);

        byte[] id = "some_id".getBytes();
        byte[] secret = "top_secret".getBytes();
        
        List<byte[]> shares = splitter.split(id, 0, secret);
        
        byte[] recovered = splitter.combine(id, 0, shares);
        String recovered_value = new String(recovered, StandardCharsets.UTF_8);
        assert(recovered_value.equals("top_secret"));
    }
}
