use num_bigint::{BigUint, RandBigInt};
use num_traits::{Num, Pow};

// safe prime in RFC3526 https://datatracker.ietf.org/doc/rfc3526/
const SAFE_PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

#[derive(Debug, Clone)]
pub struct SimpleDiffieHellman {
    // secret private key
    pk: BigUint,

    // The primitive root or generator
    pub g: BigUint,

    // The (safe) prime number
    pub p: BigUint,
}

impl SimpleDiffieHellman {
    pub fn new(g: BigUint, p: BigUint) -> Self {
        SimpleDiffieHellman {
            g,
            p,
            pk: Self::gen_pk(),
        }
    }

    /// Generates a private key within the Sophie Germain prime subgroup.
    ///
    /// Returns a random public key as a `BigUint`.
    pub fn gen_pk() -> BigUint {
        let mut rng = rand::thread_rng();

        let (_safe_prime, sophie_prime) = Self::generate_safe_prime_and_sophie_prime();

        // Generate a random private key within the Sophie Germain prime subgroup
        rng.gen_biguint_range(&BigUint::from(1u64), &sophie_prime)
    }

    /// Calculate a safe prime and its corresponding Sophie Germain prime.
    ///
    /// Returns a tuple containing the safe prime and Sophie Germain prime.
    pub fn generate_safe_prime_and_sophie_prime() -> (BigUint, BigUint) {
        // Parse the safe prime from a hexadecimal constant
        let safe_prime =
            BigUint::from_str_radix(SAFE_PRIME_HEX, 16).expect("Failed to parse safe prime");

        // Calculate the Sophie Germain prime (q) as half of the safe prime
        let sophie_prime = (&safe_prime - BigUint::from(1u64)) / BigUint::from(2u64);

        (safe_prime, sophie_prime)
    }

    // The public key is derived `Generator^Private_Key MOD Prime`
    pub fn gen_public_key(&self) -> BigUint {
        self.g.modpow(&self.pk, &self.p)
    }
    // The shared secret is derived `Public_Key^Private_Key MOD Prime`
    pub fn calculate_shared_secret(&self, public_key: &BigUint) -> BigUint {
        public_key.modpow(&self.pk, &self.p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_diffie_hellman() {
        let g = BigUint::from(2u64);

        let (_sophie_prime, safe_prime) =
            SimpleDiffieHellman::generate_safe_prime_and_sophie_prime();

        let alice = SimpleDiffieHellman::new(g, safe_prime);

        let bob = alice.clone();

        let alice_public_key = alice.gen_public_key();

        let bob_public_key = bob.gen_public_key();

        let alice_version_of_shared_secret = alice.calculate_shared_secret(&bob_public_key);

        let bob_version_of_shared_secret = bob.calculate_shared_secret(&alice_public_key);

        assert!(
            alice_version_of_shared_secret.eq(&bob_version_of_shared_secret)
        );
    }
}
