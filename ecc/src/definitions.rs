use num_bigint::BigInt;

// A tuple struct representing a point with two BigUint coordinates (x, y).

#[derive(PartialEq, Debug, Clone)]
pub struct Point(pub BigInt, pub BigInt);

impl Point {
    pub fn to_hex_string(&self) -> String {
        let hex_string = hex::encode(format!("{}{}", self.0.to_string(), self.1.to_string()));
        format!("04{}", hex_string)
    }
}

/// Represents a point on an elliptic curve.
#[derive(PartialEq, Debug)]
pub enum EccPoint {
    // A point with finite coordinates represented by a `Point` tuple struct.
    Finite(Point),
    // The point at infinity, acting as the identity element in elliptic curve arithmetic.
    Infinity,
}

/// Represents the supported elliptic curves.
///
/// # Variants
/// * `Secp256k1` - Represents the secp256k1 curve.
pub enum Curve {
    Secp256k1,
}

/// Defines the behavior for an elliptic curve.
pub trait EllipticCurve {
    // Adds two points on the elliptic curve and returns the resulting point.
    fn add_points(&self, a: &EccPoint, b: &EccPoint) -> EccPoint;

    // Doubles a point on the elliptic curve.
    fn double_point(&self, a: &EccPoint) -> EccPoint;
}
