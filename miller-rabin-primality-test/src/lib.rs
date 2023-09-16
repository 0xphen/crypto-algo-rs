pub struct MRPT;

impl MRPT {
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
        let mut k: u32 = 1;
        let mut m: u32 = 0;

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
}
