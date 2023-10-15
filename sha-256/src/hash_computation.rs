pub mod message_schedule {
    use crate::constants;
    use crate::preprocess::*;
    use crate::utilities;

    #[derive(Debug)]
    pub struct MessageSchedule {
        pub w: Vec<[[u8; 4]; 64]>,
        pub working_vars: [[u8; 4]; 8],
    }

    impl MessageSchedule {
        /// Constructs a new `MessageSchedule` from the given preprocessed data.
        ///
        /// The function divides the preprocessed message into blocks of 512 bits
        /// (64 bytes). Each of these blocks is further divided into sixteen 32-bit
        /// (4 bytes) words to create the message schedule required for SHA-256.
        ///
        /// # Arguments
        /// * `preprocess_data` - Contains the preprocessed message.
        ///
        /// # Returns
        /// A new `MessageSchedule` instance.
        pub fn new(preprocess_result: PreprocessResult) -> Self {
            let n = preprocess_result.0.len();
            let mut schedule: Vec<[[u8; 4]; 64]> = vec![];

            for idx in 0..n {
                let mut block: [[u8; 4]; 64] = [[0; 4]; 64];

                for t in 0..=63 {
                    block[t] = match t {
                        // W0 - W15 is same as M0_n - M15_n
                        0..=15 => (preprocess_result.0)[idx][t],

                        16..=63 => {
                            let ssig1 = MessageSchedule::ssig1(block[t - 2]);
                            let ssig0 = MessageSchedule::ssig0(block[t - 15]);

                            let w_1 = block[t - 7];
                            let w_2 = block[t - 16];

                            let mut w = utilities::add_mod_2(ssig1, ssig0);

                            w = utilities::add_mod_2_32(w, w_1);
                            utilities::add_mod_2_32(w, w_2)
                        }

                        _ => panic!("Unexpected value for t"),
                    };

                    schedule.push(block);
                }
            }

            MessageSchedule {
                w: schedule,
                working_vars: MessageSchedule::init_working_vars(),
            }
        }

        pub fn init_working_vars() -> [[u8; 4]; 8] {
            let mut result: [[u8; 4]; 8] = Default::default();

            for (i, &h) in constants::H.iter().enumerate() {
                result[i] = hex_to_byte_array(h);
            }

            result
        }

        /// Compute the small sigma 1 function, as part of some cryptographic operation.
        /// This involves bitwise rotations and shifts.
        pub fn ssig1(x: [u8; 4]) -> [u8; 4] {
            let result = utilities::add_mod_2(utilities::rotr(x, 17), utilities::rotr(x, 19));
            utilities::add_mod_2(result, utilities::shr(x, 10))
        }

        /// Compute the small sigma 0 function, as part of some cryptographic operation.
        /// This involves bitwise rotations and shifts.
        pub fn ssig0(x: [u8; 4]) -> [u8; 4] {
            let result = utilities::add_mod_2(utilities::rotr(x, 7), utilities::rotr(x, 18));
            utilities::add_mod_2(result, utilities::shr(x, 3))
        }
    }
}

pub mod compression {
    use super::message_schedule::MessageSchedule;

    use crate::constants::{H, K};
    use crate::preprocess::hex_to_byte_array;
    use crate::utilities::{add_mod_2_32, and, not, rotr, xor};

    /// Performs the SHA-256 compression on a given message schedule.
    ///
    /// This function modifies the working variables using the SHA-256 algorithm.
    ///
    /// # Arguments
    /// * `msg_schedule` - The message schedule containing the working variables and data to be compressed.
    ///
    /// # Returns
    /// * An array of the compressed working variables `a` through `h`.
    pub fn compress(msg_schedule: MessageSchedule) -> [[u8; 4]; 8] {
        // Temporary variables for intermediate results
        let mut t_1: [u8; 4];
        let mut t_2: [u8; 4];

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = msg_schedule.working_vars;

        // Iterate through each block in the message schedule
        for n in 0..msg_schedule.w.len() {
            // Process each of the 64 rounds
            for idx in 0..=63 {
                t_1 = compute_t_1(
                    e,
                    f,
                    g,
                    h,
                    hex_to_byte_array(K[idx]),
                    msg_schedule.w[n][idx],
                );

                t_2 = compute_t_2(
                    msg_schedule.working_vars[0],
                    msg_schedule.working_vars[1],
                    msg_schedule.working_vars[2],
                );

                // Update the working variables according to the SHA-256 specifications
                h = g;
                g = f;
                f = e;
                e = add_mod_2_32(d, t_1);
                d = c;
                c = b;
                b = a;
                a = add_mod_2_32(t_1, t_2);
            }
        }

        [a, b, c, d, e, f, g, h]
    }

    /// Computes the digest from a given set of intermediate hash values.
    /// This function adds each compressed chunk to its corresponding current hash value
    /// from the provided intermediate hash matrix (`ihm`). It then appends all the resulting
    /// hash values together to form a byte array representing the final hash.
    ///
    /// # Arguments
    ///
    /// * `ihm` - An array of intermediate hash values, where each entry is a 4-byte array.
    ///
    /// # Returns
    ///
    /// A 32-byte array representing the final hash value.
    ///
    /// # Panics
    ///
    /// Panics if the provided `ihm` array does not have the expected size.
    pub fn compute_bytes_digest(ihm: [[u8; 4]; 8]) -> [u8; 32] {
        // Initialize a default hash matrix.
        let mut h: [[u8; 4]; 8] = Default::default();

        // Update the hash matrix by adding the compressed chunk to the corresponding
        // current hash value from the intermediate hash matrix.
        for i in 0..H.len() {
            // Add the current hash value from ihm to the corresponding initial hash value
            h[i] = add_mod_2_32(hex_to_byte_array(H[i]), ihm[i]);
        }

        // Flatten, copy, and collect the hash matrix into a single byte array.
        h.iter()
            .flatten()
            .copied()
            .enumerate()
            .fold([0u8; 32], |mut acc, (idx, byte)| {
                acc[idx] = byte;
                acc
            })
    }

    fn compute_t_1(
        e: [u8; 4],
        f: [u8; 4],
        g: [u8; 4],
        h: [u8; 4],
        k: [u8; 4],
        w: [u8; 4],
    ) -> [u8; 4] {
        let bssig1 = xor(xor(rotr(e, 6), rotr(e, 11)), rotr(e, 25)); // We can do this due to the associative property of XOR.
        let ch = xor(and(e, f), and(not(e), g));

        add_mod_2_32(
            add_mod_2_32(add_mod_2_32(add_mod_2_32(h, bssig1), ch), k),
            w,
        )
    }

    fn compute_t_2(a: [u8; 4], b: [u8; 4], c: [u8; 4]) -> [u8; 4] {
        let bssig0 = xor(xor(rotr(a, 2), rotr(a, 13)), rotr(a, 22));

        let maj = xor(xor(and(a, b), and(a, c)), and(b, c));

        add_mod_2_32(bssig0, maj)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::preprocess;

    #[test]
    fn init_message_schedule() {
        let processed_result = preprocess::preprocess_message("hello world");
        let msg_schedule = message_schedule::MessageSchedule::new(processed_result);

        assert_eq!(msg_schedule.w.len(), 64);
    }
}
