use miller_rabin_primality_test::MRPT;
use utils::{modular_inverse, relative_prime};

use num_bigint::{BigInt, BigUint, Sign, ToBigInt};
use rand::{thread_rng, RngCore};

// The public exponent is hardcoded as `65537` cause it's
// a Fermat's prime and and it's large enough to be secure against certain
// attacks while still being small enough to allow for efficient encryption operations.
const E: u64 = 65537;

pub struct RSA {
    d: BigInt,
    pub n: BigInt,
    pub e: BigInt,
}

impl RSA {
    pub fn new() -> Self {
        let p = Self::gen_1024_prime().to_bigint().unwrap();
        let q = Self::gen_1024_prime().to_bigint().unwrap();
        let n: BigInt = (&p * &q).to_bigint().unwrap();

        // ϕ(N) is multiplicative. Since N = p * q
        // ϕ(p * q) = ϕ(p) * ϕ(q)
        let phi_n = (&p - 1) * (&q - 1);

        let e = BigInt::from(E);
        // Ensure `e` and `phi_n` are relative prime
        if !relative_prime::is_co_prime(&phi_n, &e) {
            panic!("{} and {} are not co-prime", e, phi_n);
        }

        // The decryption key `d` is the multiplicative inverse of
        // `E` mod `n`
        let d = modular_inverse::mod_inverse(e.clone(), phi_n);

        RSA { d, n, e }
    }

    fn gen_1024_prime() -> BigUint {
        let mut rng = thread_rng();

        loop {
            println!("Deriving 1024 bit prime...");
            let mut bytes = [0u8; 128]; // 128 bytes = 1024 bits
            rng.fill_bytes(&mut bytes);

            // Ensure the number is odd by setting the last bit to 1
            bytes[127] |= 1;
            let p = BigUint::from_bytes_be(&bytes);

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
    fn test_rsa() {
        let msg = BigInt::from(4i32);

        let rsa = RSA::new();

        // Encrypt message
        let cipher_text = BigInt::modpow(&msg, &rsa.e, &rsa.n);

        // Decrypt `cipher_text` using decryption key
        let decrypted_msg = BigInt::modpow(&cipher_text, &rsa.d, &rsa.n);

        assert_eq!(msg, decrypted_msg);
    }
}
