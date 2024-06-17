package com.example;

import org.derecalliance.derec.crypto.DerecCryptoImpl;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        DerecCryptoImpl cryptoImpl = new DerecCryptoImpl();

        byte[] id = "some_id".getBytes();
        byte[] secret = "top_secret".getBytes();

        List<byte[]> shares = cryptoImpl.share(id, 0, secret, 5, 3);
        byte[] recovered = cryptoImpl.recover(id, 0, shares);

        String recovered_value = new String(recovered, StandardCharsets.UTF_8);
        assert(recovered_value.equals("top_secret"));
        System.out.println(recovered_value);

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
        assert(recovered_value.equals("top_secret"));
        System.out.println(recovered_value);
    }
}
