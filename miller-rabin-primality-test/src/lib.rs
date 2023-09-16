pub struct MRPT;

impl MRPT {
    pub fn is_prime(p: u32) -> bool {
        //Step 1: derive m and k
        let (_k, m) = MRPT::derive_k_and_m(p);

        // step 2: select a
        // we choose any value of a in the range 1 < a < p - 1.
        let a = 2;

        // step 3: derive b
        let b = MRPT::derive_b(a, m, p);
        println!("SEE: {:?}", b);
        if b == 1 {
            return false;
        }

        return true;
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
    pub fn derive_k_and_m(p: u32) -> (u32, u32) {
        let k: u32;
        let m: u32;

        // Closure to solve the equation `n-1/2^k`
        // It returns a tuple containing two values: `m` and `k` respectively.
        // a and b represents `n-1` and k respectively.
        let k_and_m = |a: u32, b: u32| -> (f32, u32) {
            let m = (a as f32 / (2_f32.powf(b as f32))) as f32;
            (m, b)
        };

        let mut temp_k: u32 = 0;
        let mut temp_m: f32 = 0.0;

        loop {
            let (a, b) = k_and_m(p - 1, temp_k + 1);
            // If a is not an integer, then we set `m` to the previous value
            //of m `temp_m`, and `k` to the previous value of k `temp_k`
            if a.fract() > 0.0 {
                k = temp_k;
                m = temp_m as u32;
                break;
            }

            // Increment k (`temp_k`)
            temp_k += 1;
            temp_m = a;
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
    /// * 'p' - The prime number
    ///
    /// # Returns
    /// A signed integer - either +1 or -1
    ///
    /// A boolean indicating if the number is prime or composite.
    pub fn derive_b(a: u32, m: u32, p: u32) -> i32 {
        let mut b = (a as i32).pow(m) % p as i32;

        loop {
            b = (b.pow(2)) % p as i32;
            
            if b == 1 || b == -1 {
                break;
            }
        }

        b
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
        let (_k, m) = MRPT::derive_k_and_m(p);
        let b = MRPT::derive_b(2, m, p);

        assert_eq!(b, 1);
    }

    #[test]
    fn test_is_prime() {
        let p = 7;
        let is_prime = MRPT::is_prime(p);

        assert_eq!(is_prime, false);
    }
}
