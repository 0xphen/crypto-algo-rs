use num_bigint::BigInt;

// A tuple struct representing a point with two BigUint coordinates (x, y).

#[derive(PartialEq, Debug, Clone)]
pub struct Point(pub BigInt, pub BigInt);

/// Represents a point on an elliptic curve.
#[derive(PartialEq, Debug)]
pub enum EccPoint {
    // A point with finite coordinates represented by a `Point` tuple struct.
    Finite(Point),
    // The point at infinity, acting as the identity element in elliptic curve arithmetic.
    Infinity,
}

/// Defines the behavior for an elliptic curve.
pub trait EllipticCurve {
    // Adds two points on the elliptic curve and returns the resulting point.
    fn add_points(&self, a: &EccPoint, b: &EccPoint) -> EccPoint;

    // Doubles a point on the elliptic curve.
    fn double_point(&self, a: &EccPoint) -> EccPoint;
}
