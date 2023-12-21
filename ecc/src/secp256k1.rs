use std::ops::{Mul, Sub};

use num_bigint::BigInt;
use num_traits::{Num, One, Zero};

use super::{definitions::*, util::*};

pub const X: &str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
pub const Y: &str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
pub const N: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
pub const A: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const B: &str = "0000000000000000000000000000000000000000000000000000000000000007";

#[derive(PartialEq)]
pub struct SECP256K1 {
    pub g: Point,
    pub n: BigInt,
    pub a: BigInt,
    pub b: BigInt,
}

impl Default for SECP256K1 {
    fn default() -> Self {
        let x: BigInt =
            BigInt::from_str_radix(X, 16).expect("Failed to parse Secp256k1-generator-x");

        let y: BigInt =
            BigInt::from_str_radix(Y, 16).expect("Failed to parse Secp256k1-generator-y");

        let n: BigInt =
            BigInt::from_str_radix(N, 16).expect("Failed to parse Secp256k1-group-order");

        let a: BigInt = BigInt::from_str_radix(A, 16).expect("Failed to parse Secp256k1-a");

        let b: BigInt = BigInt::from_str_radix(B, 16).expect("Failed to parse Secp256k1-b");

        Self {
            g: Point(x, y),
            n,
            a,
            b,
        }
    }
}

impl EllipticCurve for SECP256K1 {
    /// Doubles a point on an elliptic curve.
    ///
    /// This function takes a point on the elliptic curve and returns a new point
    /// that is the result of doubling the input point according to elliptic curve
    /// arithmetic. The point doubling is done modulo the curve's defined prime field.
    ///
    /// # Arguments
    /// * `ecc_point` - A reference to `EccPoint`, which can either be a finite point
    ///                 on the curve or the point at infinity.
    ///
    /// # Returns
    /// Returns `EccPoint`, which is either:
    /// * A finite point resulting from the doubling operation.
    /// * The point at infinity if the input is the point at infinity or if the result
    ///   of the doubling operation leads to the point at infinity (e.g., when the
    ///   y-coordinate of the input point is zero).
    fn double_point(&self, ecc_point: &EccPoint) -> EccPoint {
        match ecc_point {
            EccPoint::Finite(point) => {
                if point.1.is_zero() {
                    return EccPoint::Infinity;
                }

                let numerator = (BigInt::from(3u32) * (point.0).pow(2) + &self.a) % &self.n;

                let denominator = BigInt::from(2u32) * &point.1;

                // Slope
                let lambda = (numerator * mod_inv(&denominator, &self.n)) % &self.n;

                let x3 = (lambda.pow(2) - (&point.0 * BigInt::from(2u32))) % &self.n;

                let y3 = (lambda * (&point.0 - &x3) - &point.1) % &self.n;
                let y3 = if y3 < BigInt::zero() { y3 + &self.n } else { y3 };

                EccPoint::Finite(Point(x3, y3))
            }

            _ => EccPoint::Infinity,
        }
    }

    fn add_points(&self, a: &EccPoint, b: &EccPoint) -> EccPoint {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;

    use super::*;

    lazy_static! {
        static ref SECP256K1_CURVE: SECP256K1 = SECP256K1::default();
        static ref MOCK_SECP256K1_CURVE: SECP256K1 = SECP256K1 {
            g: Point(BigInt::from(5i32), BigInt::from(1i32),),
            n: BigInt::from(17i32),
            a: BigInt::from(2i32),
            b: BigInt::from(2i32)
        };
    }

    #[test]
    fn double_point_test() {
        let new_point = MOCK_SECP256K1_CURVE.double_point(&EccPoint::Finite(Point(
            BigInt::from(5i32),
            BigInt::from(1i32),
        )));

        assert!(new_point == EccPoint::Finite(Point(BigInt::from(6i32), BigInt::from(3i32))));
    }
}
