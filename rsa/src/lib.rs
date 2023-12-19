use miller_rabin_primality_test::MRPT;
use utils::{modular_inverse, relative_prime};

use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};
use rand::{thread_rng, RngCore};
use rayon::prelude::*;

// Public exponent used for RSA. 65537 is chosen because it's a Fermat prime and commonly used.
const E: u64 = 65537;

pub struct RSA {
    d: BigInt,     // The private exponent.
    pub n: BigInt, // The modulus for both the public and private keys.
    pub e: BigInt, // The public exponent.
}

impl Default for RSA {
    fn default() -> Self {
        RSA::new()
    }
}

impl RSA {
    /// Constructs a new RSA instance with generated keys.
    pub fn new() -> Self {
        // Generate two distinct primes, p and q, for RSA.
        let primes: Vec<_> = (0..2)
            .into_par_iter()
            .map(|_| Self::gen_1024_prime())
            .collect();

        let p = primes[0].to_bigint().unwrap();
        let q = primes[1].to_bigint().unwrap();

        // Calculate the modulus n which is the product of p and q.
        let n: BigInt = (&p * &q).to_bigint().unwrap();

        // Calculate Euler's totient function, phi(n), which is (p-1)*(q-1).
        // ϕ(N) is multiplicative. Since N = p * q,
        // hence ϕ(p * q) = ϕ(p) * ϕ(q)
        let phi_n = (&p - 1) * (&q - 1);

        // Create BigInt from the constant exponent.
        let e = BigInt::from(E);

        // Check if e and phi_n are co-prime, which they should be by the choice of e.
        if !relative_prime::is_co_prime(&phi_n, &e) {
            panic!("{} and {} are not co-prime", e, phi_n);
        }

        // Calculate the private exponent d, the modular inverse of e mod phi_n.
        let d = modular_inverse::mod_inverse(e.clone(), phi_n);

        RSA { d, n, e }
    }

    pub fn encrypt(&self, msg: &BigInt) -> BigInt {
        BigInt::modpow(msg, &self.e, &self.n)
    }

    pub fn decrypt(&self, c: BigInt) -> BigInt {
        BigInt::modpow(&c, &self.d, &self.n)
    }

    /// Generates a random 1024-bit prime number for RSA key generation.
    fn gen_1024_prime() -> BigUint {
        let mut rng = thread_rng();
        println!("Deriving 1024 bit prime...");

        loop {
            // Create a 128-byte buffer, which equates to 1024 bits.
            let mut bytes = [0u8; 128];
            rng.fill_bytes(&mut bytes);

            // Set the least significant bit to 1 to ensure the number is odd.
            bytes[127] |= 1;
            let p = BigUint::from_bytes_be(&bytes);

            // Use the Miller-Rabin primality test to check if the number is prime.
            if MRPT::is_prime(&p) {
                println!("Found 1024 bit prime: {:?}", p);
                return p;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_test() {
        let msg = BigInt::from(4i32);

        let rsa = RSA::default();

        let cipher_text = rsa.encrypt(&msg);
        let decrypted_msg = rsa.decrypt(cipher_text);

        assert_eq!(msg, decrypted_msg);
    }
}
