use crypto_bigint::{Wrapping, U256};

pub struct MRPT;

impl MRPT {
    pub fn is_prime(p: u32) -> bool {
        //Step 1: derive m and k
        let (k, m) = MRPT::derive_k_and_m(p);

        // step 2: select `a`
        // we choose any value of a in the range 1 < a < p - 1.
        let a = 2;

        // step 3: derive b
        let (n, i) = MRPT::derive_b(a, m, k, p);

        // If `i` == 1, then `n` can be either -1 or 1,
        // and this means `p` is a probably a prime number.
        // If `i` > 1, then `p` is probably prime if `n` == -1
        if i == 1 && (n == 1 || n == -1) || (i != 1 && n == -1) {
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
    fn derive_k_and_m(p: u32) -> (u32, u32) {
        let k: u32;
        let m: u32;

        let mut temp_k: u32 = 0;
        let mut temp_m: u32 = 0;
        let n = p - 1;

        loop {
            // To derive `m` and `k`, we use the formula: `n-1/2^k`.
            // If the result is a floating number, then `m` and `k` will
            // be the previous values of `temp_m` and `temp_k`.
            // To check if `n-1/2^k` is a float, we take the modulus of
            // `n mod 2^k-1`.
            if n % (2_u32.pow(temp_k + 1)) == 0 {
                temp_m = n / 2_u32.pow(temp_k + 1);
                temp_k += 1;

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
    fn derive_b(a: u32, m: u32, k: u32, p: u32) -> (i32, u32) {
        let mut b: i32 = 0;
        for i in 0..k {
            // For the first iteration (i = 0), calculate b using: a^m mod p.
            // If a^m congruent to -1 mod p or = mod p, then `p` is prime.
            if i == 0 {
                b = (a as i32).pow(m) % p as i32;

                let congruent_to_negative_one = MRPT::is_congruent(p as i32, b as u32, -1);

                let congruent_to_one = MRPT::is_congruent(p as i32, b as u32, 1);

                if congruent_to_negative_one && congruent_to_one {
                    // Return either 1 or -1; since in the first iteration
                    // 1 or -1 means `p` is prime. Caller should use the 2nd
                    // element in the tuple `i` to deduce if prime or not.
                    return (-1, i);
                }
            } else {
                b = (b.pow(2)) % p as i32;

                // From the second iteration to the last i.e
                // from `k = 0` to `k = k - 1`, `p` is probably prime
                // if `b` is congruent to `-1 mod p`.
                let congruent_to_negative_one = MRPT::is_congruent(p as i32, b as u32, -1);

                if congruent_to_negative_one {
                    return (-1, i);
                }
            }
        }

        return (b, k);
    }

    /// Checks if a number is congruent to another number
    /// modulo a given modulus.
    ///
    /// # Arguments
    ///
    /// * `m` - The modulus.
    /// * `a` - The first number.
    /// * `b` - The second number to which `a` is compared for congruence
    fn is_congruent(m: i32, a: u32, b: i32) -> bool {
        // We need to handle a scenario when `b` is negative.
        // For example, the result of -1 mod m (where m > 0), is m -1.
        // In rust, the `%` operator calculates the remainder, and when
        // applied to a negative number (example -1 mod m), it returns a
        // negative number (-1), instead of `m - 1`.
        // We ensure that the result is a positive remainder within
        // the range [0, m-1]
        (a as i32 % m) == (b % m + m) % m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k_and_m() {
        let (k, m) = MRPT::derive_k_and_m(561);

        assert_eq!(k, 4);
        assert_eq!(m, 35);
    }

    #[test]
    fn test_derive_b() {
        let p = 53;
        let (k, m) = MRPT::derive_k_and_m(p);
        let (n, i) = MRPT::derive_b(2, m, k, p);

        assert_eq!(n, -1);
    }

    #[test]
    fn test_is_prime() {
        let p = 61;
        let is_prime = MRPT::is_prime(p);

        assert_eq!(is_prime, true);
    }

    #[test]
    fn test_is_congruent() {
        let is_congruent = MRPT::is_congruent(10, 52, 2);

        assert_eq!(is_congruent, true);
    }
}
