/// This module performs the preprocessing of a message.
/// Preprocessing involves 3 steps:
/// 1. Padding a message.
/// 2. Parsing the message into message blocks.
/// 3. Setting the initial hash value `H_0`.
pub mod preprocess {
    use crate::constants;

    const CHUNK_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 512;

    #[derive(Debug)]
    pub struct PreprocessResult {
        pub processed_msg: String,
        pub initial_hash_value: String,
        pub msg_blocks: Vec<Vec<String>>,
    }

    /// Converts a message to binary and pads the binary to SHA-256 specifications.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to process.
    ///
    /// # Returns
    /// A PreprocessResult.
    pub fn preprocess_message(message: &str) -> PreprocessResult {
        let mut msg_binary = String::new();

        let padded_msg = pad_binary(convert_msg_to_binary(message).as_str());

        let msg_blocks = generate_message_blocks(&padded_msg);

        return PreprocessResult {
            processed_msg: padded_msg,
            initial_hash_value: constants::H_0.to_string(),
            msg_blocks,
        };
    }

    /// Converts a hexadecimal value to its binary representation
    ///
    /// # Arguments
    /// * `hex_str` - Hexadecimal value
    ///
    /// # Returns
    /// The binary representation of `hex_str`
    fn convert_hex_to_binary(hex_str: &str) -> String {
        hex_str
            .chars()
            .collect::<Vec<_>>()
            .iter()
            .map(|c| format!("{:04b}", c.to_digit(16).expect("Failed to parse hex")))
            .collect::<String>()
    }

    /// Convert an input to binary
    ///
    /// # Arguments
    ///
    /// * `message` - the input data
    ///
    /// # Returns
    /// A binary representation of the `message`
    fn convert_msg_to_binary(message: &str) -> String {
        message
            .as_bytes()
            .into_iter()
            .map(|byte| format!("{:08b}", byte))
            .collect::<String>()
    }

    /// Pad the binary to the right as follows:
    /// append `1`,
    /// append K `0's`, where k = (448 - L - 1) mod 512.
    /// append the length `L` of the binary, where L has been converted to binary
    /// and is a 64-bit representation of the length.
    ///
    /// # Arguments
    ///
    /// * `b` - the binary
    ///
    /// # Returns
    /// The padded binary
    fn pad_binary(b: &str) -> String {
        let mut padded_binary = format!("{}{}", b, 1); // append 1 to the binary
        let k = (448 - b.len() - 1) % 512;
        padded_binary = format!("{}{}", padded_binary, "0".repeat(k)); // append k 0's to the binary

        let b_len_in_binary = format!("{:b}", b.len());
        // Create a 64-bit representation of the length of the binary
        let padded_b_length = format!(
            "{}{}",
            "0".repeat(64 - b_len_in_binary.len()),
            b_len_in_binary
        );

        padded_binary = format!("{}{}", padded_binary, padded_b_length); // append the 64-bit length to the binary.
        return padded_binary;
    }

    /// The message and its padding is parsed into N 512-bit blocks.
    /// And each 512-bit block is further parsed into sixteen 32-bit blocks.
    ///
    /// # Arguments
    /// * `msg_binary` - The padded binary message
    ///
    /// # Returns
    /// A nested array
    fn generate_message_blocks(msg_binary: &str) -> Vec<Vec<String>> {
        //Parse the padded message into N 512-bit blocks.
        let n_512_bit_blocks: Vec<String> = msg_binary
            .chars()
            .collect::<Vec<_>>()
            .chunks(BLOCK_SIZE)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect();

        // Further parse each 512-bit block, into sixteen 32-bit blocks.
        n_512_bit_blocks
            .iter()
            .map(|block| {
                block
                    .chars()
                    .collect::<Vec<_>>()
                    .chunks(CHUNK_SIZE)
                    .map(|chunk| chunk.iter().collect::<String>())
                    .collect()
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const MESSAGE: &str = "hello world";
        const MSG_TO_BINARY: &str = "0110100001100101011011000110110001101111001000000111011101101111011100100110110001100100";

        const PADDED_MESSAGE: &str = "01101000011001010110110001101100011011110010000001110111011011110111001001101100011001001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001011000";

        #[test]
        fn pad_message() {
            let binary = convert_msg_to_binary(MESSAGE);
            assert_eq!(binary, MSG_TO_BINARY);

            let padded_binary = pad_binary(&binary);
            assert_eq!(padded_binary, PADDED_MESSAGE);
        }

        #[test]
        fn parse_blocks() {
            let n_512_blocks = generate_message_blocks(&PADDED_MESSAGE);

            assert_eq!(n_512_blocks.len(), PADDED_MESSAGE.len() / 512);

            for block in n_512_blocks {
                assert_eq!(block.len(), 16);
                for word in block {
                    assert_eq!(word.len(), 32);
                }
            }
        }

        #[test]
        fn preprocess() {
            let result = preprocess_message(MESSAGE);
            println!("result:: {:?}", result);
        }
    }
}
