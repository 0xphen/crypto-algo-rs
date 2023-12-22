use num_bigint::BigInt;
use num_traits::{Num, Zero};

use super::{definitions::*, util::*};

// Secp256k1 domain parameters
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
                let slope = (numerator * mod_inv(&denominator, &self.n)) % &self.n;

                let (x3, y3) =
                    derive_new_point_coordinates(&slope, &point.0, &point.0, &point.1, &self.n);

                EccPoint::Finite(Point(x3, y3))
            }

            _ => EccPoint::Infinity,
        }
    }

    /// Adds two points on an elliptic curve.
    ///
    /// Handles the addition of finite points and points at infinity. If the points are inverses,
    /// returns the point at infinity.
    ///
    /// # Arguments
    /// * `p1` - The first point as `EccPoint`.
    /// * `p2` - The second point as `EccPoint`.
    ///
    /// # Returns
    /// The result of the addition as `EccPoint`.
    fn add_points(&self, p1: &EccPoint, p2: &EccPoint) -> EccPoint {
        match (p1, p2) {
            (EccPoint::Finite(p1), EccPoint::Finite(p2)) => {
                // If `p1` and `p2` are inverse or symmetric over the x-axis,
                // then adding both points will result in the point at infinity.
                // Also, if `x1 == x2`, then it means that the line intersecting the two points is vertical.
                // For elliptic curves, this means that the points `P` and `Q`` add up to the point at infinity,
                // as there is no third intersection point with the curve.
                if points_inverse(p1, p2) || p2.0 == p1.0 {
                    return EccPoint::Infinity;
                }

                let numerator = (&p2.1 - &p1.1) % &self.n;
                let denominator = &p2.0 - &p1.0;
                let slope = (numerator * mod_inv(&denominator, &self.n)) % &self.n;

                let (x3, y3) = derive_new_point_coordinates(&slope, &p1.0, &p2.0, &p1.1, &self.n);

                EccPoint::Finite(Point(x3, y3))
            }
            (EccPoint::Finite(p1), EccPoint::Infinity) => EccPoint::Finite(p1.clone()),
            (EccPoint::Infinity, EccPoint::Finite(p2)) => EccPoint::Finite(p2.clone()),
            _ => EccPoint::Infinity,
        }
    }
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;
    use num_bigint::BigUint;

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

    #[test]
    fn add_points_test() {
        let p1 = Point(BigInt::from(5i32), BigInt::from(1i32));
        let p2 = Point(BigInt::from(6i32), BigInt::from(3i32));

        let mut new_point = MOCK_SECP256K1_CURVE
            .add_points(&EccPoint::Finite(p1.clone()), &EccPoint::Finite(p2.clone()));

        assert!(new_point == EccPoint::Finite(Point(BigInt::from(10i32), BigInt::from(6i32))));

        new_point =
            MOCK_SECP256K1_CURVE.add_points(&EccPoint::Finite(p1.clone()), &EccPoint::Infinity);
        assert!(new_point == EccPoint::Finite(p1.clone()));

        new_point =
            MOCK_SECP256K1_CURVE.add_points(&EccPoint::Infinity, &EccPoint::Finite(p2.clone()));
        assert!(new_point == EccPoint::Finite(p2));

        new_point = MOCK_SECP256K1_CURVE.add_points(
            &EccPoint::Finite(p1),
            &EccPoint::Finite(Point(BigInt::from(5i32), BigInt::from(16i32))),
        );

        assert!(new_point == EccPoint::Infinity);
    }

    #[test]
    fn scalar_mul_test() {
        let mut new_point = scalar_mul(
            BigUint::from(15u32),
            &Point(BigInt::from(5i32), BigInt::from(1i32)),
            &*MOCK_SECP256K1_CURVE,
        );

        assert!(new_point == EccPoint::Finite(Point(BigInt::from(3i32), BigInt::from(16i32))));

        new_point = scalar_mul(
            BigUint::from(19u32),
            &Point(BigInt::from(5i32), BigInt::from(1i32)),
            &*MOCK_SECP256K1_CURVE,
        );

        assert!(new_point == EccPoint::Infinity);
    }
}
