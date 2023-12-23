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
/// This method is preferred for its resistance to side-channel attacks, providing consistent
/// execution time and memory access patterns to protect against certain types of attacks.
///
/// Arguments:
///   * `k`: A reference to a vector of bytes representing the scalar value to multiply the point by.
///          Each byte represents a part of the scalar, typically in big-endian order. This vector
///          effectively represents the private key or scalar multiplier in binary form.
///   * `p`: A reference to the point on the elliptic curve to be multiplied. This point should be
///          a valid point on the provided curve.
///   * `ecc_curve`: A reference to the elliptic curve being used, which must implement the
/// `EllipticCurve` trait.
///
/// Returns:
///   * An `EccPoint` representing the result of scalar multiplication of `p` by `k` on the elliptic curve.
///     The result is another point on the curve.
///
/// Note: This function assumes that `k` is provided in a big-endian byte order and the most significant
///        bit  is the leftmost bit of the first byte in the vector. Ensure that `k` and `p`
///        are valid and that `p` is indeed a point on the provided elliptic curve.  Improper inputs
///        could lead to incorrect results or errors.
pub fn scalar_mul(k: &[u8], p: &Point, ecc_curve: &impl EllipticCurve) -> EccPoint {
    let mut r_0 = EccPoint::Infinity;
    let mut r_1 = EccPoint::Finite(p.clone());

    for &bit in k.iter() {
        if bit == 0 {
            r_1 = ecc_curve.add_points(&r_0, &r_1);
            r_0 = ecc_curve.double_point(&r_0);
        } else {
            r_0 = ecc_curve.add_points(&r_0, &r_1);
            r_1 = ecc_curve.double_point(&r_1);
        }
    }

    r_0
}

pub fn bytes_to_binary(i: &[u8; 32], r: &mut Vec<u8>) {
    for m in i.iter() {
        format!("{:8b}", m).chars().for_each(|b| {
            if b == '1' {
                r.push(1);
            } else {
                r.push(0)
            }
        });
    }
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
