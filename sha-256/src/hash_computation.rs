pub mod message_schedule {
    use crate::preprocess::preprocess::PreprocessResult;
    use crate::utilities;

    #[derive(Debug)]
    pub struct MessageSchedule {
        pub w: Vec<[[u8; 4]; 64]>,
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
            let mut schedule: Vec<[[u8; 4]; 64]> = Vec::with_capacity(n);

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
                }
                schedule.push(block);
            }

            MessageSchedule { w: schedule }
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::preprocess::preprocess;

    #[test]
    fn init_message_schedule() {
        let processed_result = preprocess::preprocess_message("hello world");
        let msg_schedule = message_schedule::MessageSchedule::new(processed_result);

        for m in msg_schedule.w {
            assert_eq!(m.len(), 64);
        }
    }
}
