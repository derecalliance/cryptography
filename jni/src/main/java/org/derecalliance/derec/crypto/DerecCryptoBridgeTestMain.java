package org.derecalliance.derec.crypto;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.derecalliance.derec.crypto.DerecCryptoInterface;
import org.derecalliance.derec.crypto.DerecCryptoImpl;

public class DerecCryptoBridgeTestMain {
    public static void main(String[] args) {
        DerecCryptoImpl cryptoImpl = new DerecCryptoImpl();

        String expected_value = "top_secret";
        byte[] id = expected_value.getBytes();
        byte[] secret = expected_value.getBytes();
        
        List<byte[]> shares = cryptoImpl.share(id, 0, secret, 5, 3);
        byte[] recovered = cryptoImpl.recover(id, 0, shares);

        String recovered_value = new String(recovered, StandardCharsets.UTF_8);
        assert(recovered_value.equals(expected_value));

        Object[] enc_key = cryptoImpl.encryptionKeyGen();
        byte[] alice_ek = (byte[]) enc_key[0];
        byte[] alice_dk = (byte[]) enc_key[1];

        Object[] sign_key = cryptoImpl.signatureKeyGen();
        byte[] alice_vk = (byte[]) sign_key[0];
        byte[] alice_sk = (byte[]) sign_key[1];

        enc_key = cryptoImpl.encryptionKeyGen();
        byte[] bob_ek = (byte[]) enc_key[0];
        byte[] bob_dk = (byte[]) enc_key[1];

        sign_key = cryptoImpl.signatureKeyGen();
        byte[] bob_vk = (byte[]) sign_key[0];
        byte[] bob_sk = (byte[]) sign_key[1];


        byte[] ciphertext = cryptoImpl.signThenEncrypt(secret, alice_sk, bob_ek);
        byte[] plaintext = cryptoImpl.decryptThenVerify(ciphertext, alice_vk, bob_dk);
        recovered_value = new String(recovered, StandardCharsets.UTF_8);
        assert(recovered_value.equals(expected_value));

        ciphertext = cryptoImpl.encrypt(secret, bob_ek);
        plaintext = cryptoImpl.decrypt(ciphertext, bob_dk);
        recovered_value = new String(recovered, StandardCharsets.UTF_8);
        assert(recovered_value.equals(expected_value));

        byte[] signature = cryptoImpl.sign(secret, alice_sk);
        boolean valid = cryptoImpl.verify(secret, signature, alice_vk)[0] == 1;
        assert(valid);

        System.out.println(recovered_value);
    }
}
