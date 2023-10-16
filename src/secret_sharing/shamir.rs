//! Implements functions for Shamir secret sharing, as adapted
//! from the definition in Fig 7 of https://eprint.iacr.org/2020/800.pdf

use ark_poly::{Polynomial, univariate::DensePolynomial};
use ark_std::UniformRand;
use ark_ff::{PrimeField, BigInteger};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use rand::Rng;

use crate::secret_sharing::*;

// for now we'll use the prime field underlying the BLS12-381 G1 curve.
use ark_bls12_381::Fr as F;

pub fn share<R: Rng>(
    secret: &[u8; λ], 
    access: (u64, u64),
    rng: &mut R
) -> Vec<(u64, Vec<u8>)> {
    //convert byte array to bit array for BigInt conversion
    let secret_bits = bytes_to_bits_be(secret);
    let secret_bigint = BigInteger::from_bits_be(&secret_bits);

    let (t, n) = access;
    // degree t - 1 polynomial has t coefficients
    let mut coeffs: Vec<F> = (0..t)
        .map(|_| F::rand(rng))
        .collect();

    // f(0) must be the secret
    let secret_f = F::from_bigint(secret_bigint).unwrap();
    coeffs[0] = F::from_bigint(secret_bigint).unwrap(); //F::from_be_bytes_mod_order(secret);

    let poly = DensePolynomial { coeffs };

    let encode_f = |x: &F| -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        x.serialize_compressed(&mut buffer).unwrap();
        buffer
    };

    let shares: Vec<(u64, Vec<u8>)> = (1..n+1)
        .map(|i| (i, encode_f(&poly.evaluate(&F::from(i)))))
        .collect();

    shares
}

//for decoding: F::deserialize_compressed(buf.as_slice()).unwrap()

pub fn recover(
    access: (u64, u64),
    shares: Vec<(u64, Vec<u8>)>
) -> [u8; λ] {
    let (t, n) = access;

    let xs: Vec<u64> = shares
        .iter()
        .map(|(x, _)| *x)
        .collect();

    let shares: Vec<F> = shares
        .iter()
        .map(|(_, s)| F::deserialize_compressed(&s[..]).unwrap())
        .collect();

    //compute lagrange coefficients w.r.t. x = 0
    let lagrange_coeffs = lagrange_coefficients(&xs[..], 0);

    //secret f(0) as a field element
    let secret_f = shares
        .iter()
        .zip(lagrange_coeffs.iter())
        .fold(F::from(0), |acc, (a,b)| acc + (a * b));
    
    let secret_bigint = secret_f.into_bigint();
    let secret_bytes = secret_bigint.to_bytes_be();

    secret_bytes[λ..2*λ].try_into().unwrap()

}

fn lagrange_coefficients(xs: &[u64], x: u64) -> Vec<F> {
    let mut output = Vec::new();
    //assert!(xs.len() > 1); //undefined for 1 point
    for (i, &x_i) in xs.iter().enumerate() {
        let mut l_i = F::from(1);
        for (j, &x_j) in xs.iter().enumerate() {
            if i != j {
                let numerator = F::from(x) - F::from(x_j);
                let denominator = F::from(x_i) - F::from(x_j);
                l_i *= numerator / denominator;
            }
        }
        output.push(l_i);
    }
    output
}

fn bytes_to_bits_be(x: &[u8]) -> Vec<bool> {
    //convert byte array to bit array for BigInt conversion
    let mut output: Vec<bool> = Vec::new();

    for &byte in x {
        for i in (0..8).rev() {
            let bit = ((byte >> i) & 1) == 1;
            output.push(bit);
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn test_shamir_correctness() {
        // test if recovery on shares produces the shared secret

        //let seed: [u8; 32] = [0; 32];
        let mut rng = thread_rng();

        let mut seed = [0u8; 32];
        rng.fill(&mut seed);

        let mut secret: [u8; 16] = [0u8; 16];
        rng.fill(&mut secret);

        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

        let shares = share(&secret, (3, 5), &mut rng);
        let recovered = recover((3, 5), shares);

        assert_eq!(secret, recovered);
    }
}