use rand::prelude::*;

struct SimpleDiffieHellman {
    // secret private key
    pub pk: u32,
    // The primitive root or generator
    pub g: u32,

    // The prime number
    pub p: u32,
}

impl SimpleDiffieHellman {
    pub fn new(g: u32, p: u32) -> Self {
        SimpleDiffieHellman {
            g,
            p,
            pk: Self::gen_pk(),
        }
    }

    pub fn gen_pk() -> u32 {
        let mut rng = rand::thread_rng();
        rng.gen_range(1..=20)
    }

    // The public key is derived `Generator^Private_Key MOD Prime`
    pub fn gen_public_key(&self) -> u32 {
        (self.g ^ self.pk) % self.p
    }
    // The shared secret is derived `Public_Key^Private_Key MOD Prime`
    pub fn calculate_shared_secret(&self, public_key: u32) -> u32 {
        (public_key ^ self.pk) % self.p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: u32 = 2;
    const P: u32 = 5;

    #[test]
    fn test_simple_diffie_hellman() {
        let alice = SimpleDiffieHellman::new(G, P);
        let bob = SimpleDiffieHellman::new(G, P);

        let alice_public_key = alice.gen_public_key();

        let bob_public_key = bob.gen_public_key();

        let alice_version_of_shared_secret = alice.calculate_shared_secret(bob_public_key);

        let bob_version_of_shared_secret = bob.calculate_shared_secret(alice_public_key);

        assert_eq!(alice_version_of_shared_secret, bob_version_of_shared_secret);
    }
}
