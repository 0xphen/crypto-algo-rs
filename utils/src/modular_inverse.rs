use num_bigint::BigInt;
use num_traits::{One, Zero};

use super::relative_prime;

pub fn mod_inverse(mut a: BigInt, mut m: BigInt) -> Option<BigInt> {
    if !relative_prime::is_co_prime(&a, &m) {
        return None;
    }

    let m0 = m.clone();
    let mut y = BigInt::zero();
    let mut x = BigInt::one();

    while a > BigInt::one() {
        // q is quotient
        let q = &a / &m;
        let mut t = m.clone();

        // m is remainder now, process same as Euclid's algo
        m = a % &m;
        a = t;
        t = y.clone();

        // Update y and x
        y = &x - &q * y;
        x = t;
    }

    // Make x positive
    if x < BigInt::zero() {
        x += m0;
    }

    Some(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;

    #[test]
    fn find_mod_inverse() {
        let a = 3.to_bigint().unwrap();
        let m = 11.to_bigint().unwrap();
        assert_eq!(mod_inverse(a, m), Some(4.to_bigint().unwrap()));
    }
}
