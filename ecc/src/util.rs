use std::ops::Add;

use num_bigint::{BigInt, BigUint};
use num_traits::Zero;

use crate::definitions::{EccPoint, EllipticCurve};

use super::definitions::Point;

/// Calculates the modular inverse of `a` modulo `m` using a modified version of Fermat's theorem.
pub fn mod_inv(a: &BigInt, m: &BigInt) -> BigInt {
    a.modpow(&(m - BigInt::from(2i32)), m)
}

/// Checks if two points on an elliptic curve are inverses of each other.
pub fn points_inverse(a: &Point, b: &Point) -> bool {
    a.0 == b.0 && (&a.1).add(&b.1).is_zero()
}

/// Calculates the new point coordinates for elliptic curve operations.
///
/// # Arguments
/// * `slope` - The slope of the line.
/// * `p1_x` - The x-coordinate of the first point.
/// * `p2_x` - The x-coordinate of the second point or same as `p1_x` for doubling.
/// * `p1_y` - The y-coordinate of the first point.
/// * `n` - The modulus for the finite field.
///
/// # Returns
/// A tuple `(x3, y3)` representing the new point coordinates.
pub fn derive_new_point_coordinates(
    slope: &BigInt,
    p1_x: &BigInt,
    p2_x: &BigInt,
    p1_y: &BigInt,
    n: &BigInt,
) -> (BigInt, BigInt) {
    let mut x3 = (slope.pow(2) - (p1_x + p2_x)) % n;
    if x3 < BigInt::zero() {
        x3 += n;
    }
    let mut y3 = (slope * (p1_x - &x3) - p1_y) % n;
    if y3 < BigInt::zero() {
        y3 += n;
    }

    (x3, y3)
}

/// Performs scalar multiplication on an elliptic curve using the Montgomery Ladder algorithm.
/// This method is preferred for its resistance to side-channel attacks.
///
/// Arguments:
///   * `k`: The scalar value to multiply the point by.
///   * `p`: The point on the elliptic curve to be multiplied.
///   * `ecc_curve`: The elliptic curve being used, which implements the `EllipticCurve`` trait.
///
/// Returns:
///   * A point on the elliptic curve representing the scalar multiplication of `p` by `k`.
pub fn scalar_mul(k: BigUint, p: &Point, ecc_curve: &impl EllipticCurve) -> EccPoint {
    let mut r_0 = EccPoint::Infinity;
    let mut r_1 = EccPoint::Finite(p.clone());

    let b = format!("{:b}", k);
    for bit in b.chars() {
        if bit == '0' {
            r_1 = ecc_curve.add_points(&r_0, &r_1);
            r_0 = ecc_curve.double_point(&r_0);
        } else {
            r_0 = ecc_curve.add_points(&r_0, &r_1);
            r_1 = ecc_curve.double_point(&r_1);
        }
    }

    r_0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mod_inv_test() {
        let result = mod_inv(&BigInt::from(3i32), &BigInt::from(11i32));
        assert_eq!(result, BigInt::from(4i32));
    }

    #[test]
    fn points_inverse_test() {
        let a = BigInt::from(1i32);
        let b = BigInt::from(2i32);

        let mut is_inverse =
            points_inverse(&Point(a.clone(), b.clone()), &Point(a.clone(), -b.clone()));

        assert!(is_inverse);

        is_inverse = points_inverse(&Point(a.clone(), b.clone()), &Point(a, b));

        assert!(!is_inverse)
    }
}
