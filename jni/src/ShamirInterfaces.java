package src;

import java.security.SecureRandom;
import java.util.List;

public interface ShamirInterfaces {

   interface SplitterFactory {
       /**
        * create a new Shamir splitter
        * @param random a random number generator
        * @param count the number of shares to produce
        * @param threshold the recombination threshold
        * @return a splitter
        */
       public Splitter newSplitter(SecureRandom random, int count, int threshold);
   }


   interface Splitter {
       /**
        * Split a secret according to the parameters established
        * @param id a secret id
        * @param version a version
        * @param secret some bytes
        * @return a list of shares suitable for redistribution
        */
       public List<byte[]> split(byte[] id, int version, byte[] secret);
       public byte[] combine(byte[] id, int version, List<byte[]> shares);
   }
}