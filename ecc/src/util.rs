use std::ops::Add;

use num_bigint::BigInt;
use num_traits::Zero;

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
    let x3 = (slope.pow(2) - (p1_x + p2_x)) % n;

    let mut y3 = (slope * (p1_x - &x3) - p1_y) % n;
    if y3 < BigInt::zero() {
        y3 += n;
    }

    (x3, y3)
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
