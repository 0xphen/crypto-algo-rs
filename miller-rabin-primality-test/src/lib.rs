use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{Pow, Zero};

pub struct MRPT;

impl MRPT {
    pub fn is_prime(p: BigUint) -> bool {
        let one_biguint: BigUint = BigUint::from(1u32);
        let one_bigint: BigInt = BigInt::from(1u32);
        let negative_one_bigint: BigInt = BigInt::from(-1i32);
        let two_biguint: BigUint = BigUint::from(2u32);

        //Step 1: derive m and k
        let (k, m) = MRPT::derive_k_and_m(&p);

        // step 2: select `a`
        // we choose any value of a in the range 1 < a < p - 1.
        let a = two_biguint;

        // step 3: derive b
        let (n, itr) = MRPT::derive_b(a, &m, &k, &p);

        // If `i` == 1, then `n` can be either -1 or 1,
        // and this means `p` is a probably a prime number.
        // If `i` > 1, then `p` is probably prime if `n` == -1
        if itr.eq(&one_biguint) && (n.eq(&one_bigint) || n.eq(&negative_one_bigint))
            || (!itr.eq(&one_biguint) && n.eq(&negative_one_bigint))
        {
            return true;
        }

        return false;
    }

    /// Step 1: Derive the values for m and k
    /// using the formula n-1 = 2^k * m.
    ///
    /// # Arguments
    ///
    /// * `p` - the prime number
    ///
    /// # Returns
    /// A tuple with two elements:
    /// * `k` - the calculated value of k
    /// * `m` - the calculated value of m
    fn derive_k_and_m(p: &BigUint) -> (BigUint, BigUint) {
        let mut k: BigUint = Zero::zero();
        let mut m: BigUint = Zero::zero();

        let mut temp_k: BigUint = Zero::zero();
        let mut temp_m: BigUint = Zero::zero();

        loop {
            let exp = temp_k.clone() + 1_u32;
            let base = BigUint::from(2u32).pow(exp);

            // To derive `m` and `k`, we use the formula: `n-1/2^k`.
            // If the result is a floating number, then `m` and `k` will
            // be the previous values of `temp_m` and `temp_k`.
            // To check if `n-1/2^k` is a float, we take the modulus of
            // `n mod 2^k-1`.
            let is_float = (p - 1_u32).modpow(&BigUint::from(1u32), &base) == Zero::zero();
            if is_float {
                temp_m = (p - 1_u32).div(base);
                temp_k += 1_u32;

                continue;
            }

            k = temp_k;
            m = temp_m;
            break;
        }

        (k, m)
    }

    /// Step 2: Compute b = a^m (mod n)
    /// If b isn't +1 or -1, then recursively
    /// calculate `b` using the formula b = b^2 (mod n);
    /// until b is either +1 or -1
    ///
    /// # Arguments
    ///
    /// * `a`
    /// * `m`
    /// * `k` - The number of iterations
    /// * 'p' - The prime number
    ///
    /// # Returns
    /// A tuple with two elements:
    ///
    /// * `n` - A number (1 or -1)
    /// * `i` - The number of iterations
    fn derive_b(a: BigUint, m: &BigUint, k: &BigUint, p: &BigUint) -> (BigInt, BigUint) {
        let mut b: BigUint = Zero::zero();
        let mut itr: BigUint = Zero::zero();

        let p_bigint = p.to_bigint().unwrap();
        while itr.lt(k) {
            // For the first iteration (itr = 0), calculate b using: a^m mod p.
            // If a^m congruent to -1 mod p or = mod p, then `p` is prime.
            if itr.is_zero() {
                b = a.modpow(m, p);

                let congruent_to_negative_one =
                    MRPT::is_congruent(&p_bigint, b.to_bigint().unwrap(), BigInt::from(-1i32));

                let congruent_to_one =
                    MRPT::is_congruent(&p_bigint, b.to_bigint().unwrap(), BigInt::from(1i32));

                if congruent_to_negative_one && congruent_to_one {
                    // Return either 1 or -1; since in the first iteration
                    // 1 or -1 means `p` is prime. Caller should use the 2nd
                    // element in the tuple `i` to deduce if prime or not.
                    return (BigInt::from(-1i32), itr);
                }
            } else {
                b = b.modpow(&BigUint::from(2u32), p);

                // From the second iteration to the last i.e
                // from `k = 1` to `k = k - 1`, `p` is probably prime
                // if `b` is congruent to `-1 mod p`.
                let congruent_to_negative_one =
                    MRPT::is_congruent(&p_bigint, b.to_bigint().unwrap(), BigInt::from(-1i32));

                if congruent_to_negative_one {
                    return (BigInt::from(-1i32), itr);
                }
            }

            itr += 1u32;
        }

        return (b.to_bigint().unwrap(), k.clone());
    }

    /// Checks if a number is congruent to another number
    /// modulo a given modulus.
    ///
    /// # Arguments
    ///
    /// * `m` - The modulus.
    /// * `a` - The first number.
    /// * `b` - The second number to which `a` is compared for congruence
    fn is_congruent(m: &BigInt, a: BigInt, b: BigInt) -> bool {
        // We need to handle a scenario when `b` is negative.
        // For example, the result of -1 mod m (where m > 0), is m -1.
        // In rust, the `%` operator calculates the remainder, and when
        // applied to a negative number (example -1 mod m), it returns a
        // negative number (-1), instead of `m - 1`.
        // We ensure that the result is a positive remainder within
        // the range [0, m-1]
        let c = a.modpow(&BigInt::from(1i32), m);
        let d = b.modpow(&BigInt::from(1i32), m);
        c.eq(&d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffie_hellman_key_exchange::SimpleDiffieHellman;

    #[test]
    fn derive_k_and_m() {
        let (k, m) = MRPT::derive_k_and_m(&BigUint::from(561u32));

        assert_eq!(k, BigUint::from(4u32));
        assert_eq!(m, BigUint::from(35u32));
    }

    #[test]
    fn derive_b() {
        let p = BigUint::from(53u32);
        let (k, m) = MRPT::derive_k_and_m(&p);
        let (n, i) = MRPT::derive_b(BigUint::from(2u32), &m, &k, &p);

        assert_eq!(n, BigInt::from(-1i32));
    }

    #[test]
    fn is_prime() {
        let (_s, p) = SimpleDiffieHellman::generate_safe_prime_and_sophie_prime();

        let is_prime = MRPT::is_prime(p);
        assert_eq!(is_prime, true);
    }

    #[test]
    fn not_prime() {
        let p = BigUint::from(88u32);
        let is_prime = MRPT::is_prime(p);

        assert_eq!(is_prime, false);
    }

    #[test]
    fn is_congruent() {
        let is_congruent = MRPT::is_congruent(
            &BigInt::from(10i32),
            BigInt::from(52i32),
            BigInt::from(2i32),
        );

        assert_eq!(is_congruent, true);
    }
}
