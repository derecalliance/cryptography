package src;

import java.nio.charset.StandardCharsets;
import java.util.List;

import src.DerecCryptoInterface;
import src.DerecCryptoImpl;

public class DerecCryptoBridgeTestMain {
    public static void main(String[] args) {
        DerecCryptoImpl cryptoImpl = new DerecCryptoImpl();

        byte[] id = "some_id".getBytes();
        byte[] secret = "top_secret".getBytes();
        
        List<byte[]> shares = cryptoImpl.split(id, 0, secret, 5, 3);
        byte[] recovered = cryptoImpl.combine(id, 0, shares);

        String recovered_value = new String(recovered, StandardCharsets.UTF_8);
        assert(recovered_value.equals("top_secret"));
        System.out.println(recovered_value);

        Object[] enc_key = cryptoImpl.encryptionKeyGen();
        byte[] pk = (byte[]) enc_key[0];
        byte[] sk = (byte[]) enc_key[1];
        System.out.println("Generated pub key of length: " + pk.length);
        System.out.println("Generated priv key of length: " + sk.length);
    }
}
