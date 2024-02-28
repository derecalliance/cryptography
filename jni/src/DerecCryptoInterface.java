package src;

import java.util.List;

public interface DerecCryptoInterface {
    /**
     * Split a secret according to the parameters below
     * @param id a secret id
     * @param version a version
     * @param secret opaque byte array encoding the secret data
     * @param count number of shares
     * @param threshold reconstruction threshold
     * @return a list of byte-array shares suitable for redistribution
     */
    public List<byte[]> share(byte[] id, int version, byte[] secret, int count, int threshold);

    /**
     * Reconstruct a secret from its shares
     * @param id expected secret id
     * @param version expected version
     * @param shares list of byte-array shares
     * @return a byte-array encoded secret data
     */
    public byte[] recover(byte[] id, int version, List<byte[]> shares);

    /**
     * Generate a PEM-encoded public-private key pair
     * @return 2-dim byte array, where index 0 holds
     * the public key and index 1 holds the private key
     */
    public Object[] encryptionKeyGen();

    /**
     * Generate a PEM-encoded public-private key pair
     * @return 2-dim byte array, where index 0 holds
     * the encryption key and index 1 holds the decryption key
     */
    public Object[] signatureKeyGen();

    /**
     * sign-then-encrypt functionality
     * @param message plaintext to be signed-then-encrypted
     * @param signPrivKey private key for signing
     * @param encPubKey public key for encryption
     * @return ciphertext
     */
    public byte[] signThenEncrypt(byte[] message, byte[] signPrivKey, byte[] encPubKey);

    /**
     * decrypt-then-verify functionality
     * @param ciphertext ciphertext to be decrypted-then-verified
     * @param verifPubKey verification key
     * @param decPrivKey priv key for decryption
     * @return ciphertext
     */
    public byte[] decryptThenVerify(byte[] ciphertext, byte[] verifPubKey, byte[] decPrivKey);
}