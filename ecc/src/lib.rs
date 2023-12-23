pub mod definitions;
mod secp256k1;
pub mod util;

use rand::{rngs::OsRng, RngCore};

use crate::secp256k1::SECP256K1;
use definitions::{Curve, EccPoint};
use util::{bytes_to_binary, scalar_mul};

/// Generates a key pair (private and public) for a given elliptic curve.
///
/// Arguments:
///   * `curve`: The elliptic curve to generate keys for.
///
/// Returns:
///   * A tuple of (private_key, public_key) represented as hexadecimal strings.
pub fn generate_key_pair(curve: Curve) -> (String, String) {
    let (hex_pk, ecc_point) = match curve {
        Curve::Secp256k1 => {
            let mut secret_key = [0u8; 32];
            OsRng.fill_bytes(&mut secret_key);

            let mut bytes_key: Vec<u8> = Vec::with_capacity(32);
            bytes_to_binary(&secret_key, &mut bytes_key);

            let secp256k1 = SECP256K1::default();
            (
                hex::encode(secret_key),
                scalar_mul(&bytes_key, &secp256k1.g, &secp256k1),
            )
        }
    };

    // Convert the resulting EccPoint to a hexadecimal string for the uncompressed public key.
    let uncompressed_pub_key = match ecc_point {
        EccPoint::Finite(p) => format!("{}{}", p.0.to_str_radix(16), p.1.to_str_radix(16)),
        _ => panic!("Failed to generate public key"),
    };

    (hex_pk, uncompressed_pub_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use std::str::FromStr;

    #[test]
    fn generate_key_pair_test() {
        let (priv_key, uncompressed_pub_key) = generate_key_pair(Curve::Secp256k1);

        // Using the Rust crate `https://docs.rs/secp256k1/0.28.0/secp256k1/` as a test vector.
        let secp256k1_extern = Secp256k1::new();
        let secret_key = SecretKey::from_str(&priv_key).expect("32 bytes, within curve order");

        let pub_key = PublicKey::from_secret_key(&secp256k1_extern, &secret_key);
        let secp256k1_extern_uncompressed_pub_key = hex::encode(pub_key.serialize_uncompressed());

        assert!(format!("04{}", uncompressed_pub_key) == secp256k1_extern_uncompressed_pub_key);
    }
}
