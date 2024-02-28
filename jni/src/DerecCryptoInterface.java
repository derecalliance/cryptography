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
    public List<byte[]> split(byte[] id, int version, byte[] secret, int count, int threshold);

    /**
     * Reconstruct a secret from its shares
     * @param id expected secret id
     * @param version expected version
     * @param shares list of byte-array shares
     * @return a byte-array encoded secret data
     */
    public byte[] combine(byte[] id, int version, List<byte[]> shares);

    /**
     * Generate a PEM-encoded public-private key pair
     * @return 2-dim byte array, where index 0 holds
     * the public key and index 1 holds the private key
     */
    public Object[] encryptionKeyGen();
}