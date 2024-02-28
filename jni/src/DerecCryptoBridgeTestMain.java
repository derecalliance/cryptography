package src;

import java.nio.charset.StandardCharsets;
import java.util.List;

import src.DerecCryptoInterface;
import src.DerecCryptoImpl;

public class DerecCryptoBridgeTestMain {
    public static void main(String[] args) {
        DerecCryptoImpl splitter = new DerecCryptoImpl();

        byte[] id = "some_id".getBytes();
        byte[] secret = "top_secret".getBytes();
        
        List<byte[]> shares = splitter.split(id, 0, secret, 5, 3);
        byte[] recovered = splitter.combine(id, 0, shares);

        String recovered_value = new String(recovered, StandardCharsets.UTF_8);
        assert(recovered_value.equals("top_secret"));
        System.out.println(recovered_value);
    }
}
