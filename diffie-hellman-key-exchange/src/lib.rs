use num_bigint::{BigUint, RandBigInt};
use num_traits::Pow;

#[derive(Debug, Clone)]
struct SimpleDiffieHellman {
    // secret private key
    pub pk: BigUint,

    // The primitive root or generator
    pub g: BigUint,

    // The prime number
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

    pub fn gen_pk() -> BigUint {
        let mut rng = rand::thread_rng();
        rng.gen_biguint(100)
    }

    // The public key is derived `Generator^Private_Key MOD Prime`
    pub fn gen_public_key(&self) -> BigUint {
        // (self.g ^ self.pk) % self.p
        (self.g.clone().pow(self.pk.clone())).modpow(&BigUint::from(1u32), &self.p)
    }
    // The shared secret is derived `Public_Key^Private_Key MOD Prime`
    pub fn calculate_shared_secret(&self, public_key: BigUint) -> BigUint {
        (public_key.pow(self.pk.clone())).modpow(&BigUint::from(1u32), &self.p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_diffie_hellman() {
        let alice = SimpleDiffieHellman::new(BigUint::from(7_u32), BigUint::from(11_u32));

        let bob = alice.clone();

        let alice_public_key = alice.gen_public_key();

        let bob_public_key = bob.gen_public_key();

        let alice_version_of_shared_secret = alice.calculate_shared_secret(bob_public_key);

        let bob_version_of_shared_secret = bob.calculate_shared_secret(alice_public_key);

        assert_eq!(
            alice_version_of_shared_secret.eq(&bob_version_of_shared_secret),
            true
        );
    }
}
