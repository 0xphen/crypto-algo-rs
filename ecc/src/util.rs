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
