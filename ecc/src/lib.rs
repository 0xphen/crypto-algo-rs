pub mod definitions;
mod secp256k1;
pub mod util;

use num_bigint::BigUint;
use num_traits::Num;
use rand::{rngs::OsRng, RngCore};

use crate::secp256k1::SECP256K1;
use definitions::{Curve, EccPoint};
use util::scalar_mul;

pub fn generate_key_pair(curve: Curve) -> (String, String) {
    let mut private_key = [0u8; 32];
    OsRng.fill_bytes(&mut private_key);
    let hex_key = hex::encode(private_key);

    let ecc_point = match curve {
        Curve::Secp256k1 => {
            let secp256k1 = SECP256K1::default();

            scalar_mul(
                BigUint::from_str_radix(&hex_key, 16).expect("Failed to parse k"),
                &secp256k1.g,
                &secp256k1,
            )
        }
    };

    let pub_point = match ecc_point {
        EccPoint::Finite(p) => p,
        _ => panic!("Failed to generate public key"),
    };

    (hex_key, pub_point.to_hex_string())
}
