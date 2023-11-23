use num_bigint::BigInt;
use num_traits::{One, Zero};

pub fn is_co_prime(a: &BigInt, b: &BigInt) -> bool {
    gcd(a, b) == BigInt::one()
}

pub fn gcd(a: &BigInt, b: &BigInt) -> BigInt {
    let mut a = a.clone();
    let mut b = b.clone();

    while !b.is_zero() {
        let r = &a % &b;
        a = b;
        b = r;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;

    #[test]
    fn check_co_prime() {
        let a = 3.to_bigint().unwrap();
        let b = 11.to_bigint().unwrap();
        assert!(is_co_prime(&a, &b));
    }
}
