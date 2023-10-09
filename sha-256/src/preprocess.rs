/// This module performs the preprocessing of a message.
/// Preprocessing involves 3 steps:
/// 1. Padding a message.
/// 2. Parsing the message into message blocks.
/// 3. Setting the initial hash value `H_0`.
pub mod preprocess {
    use crate::constants;

    const BLOCK_SIZE: usize = 64;
    const CHUNK_SIZE: usize = 4;

    #[derive(Debug)]
    pub struct PreprocessResult {
        pub initial_hash_value: String,
        pub preprocessed_msg: Vec<Vec<Vec<u8>>>,
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
        let padded_msg = initial_sha256_padding(message);

        let preprocessed_msg = generate_message_blocks(padded_msg);

        return PreprocessResult {
            initial_hash_value: constants::H_0.to_string(),
            preprocessed_msg,
        };
    }

    /// Prepares a message for SHA-256 hashing by performing the initial padding.
    ///
    /// This function implements the first phase of the SHA-256 preprocessing,
    /// where the input message undergoes the following transformations:
    /// 1. A '1' bit is appended to the end.
    /// 2. '0' bits are appended to make the total length congruent to 448 (mod 512).
    /// 3. The 64-bit big-endian representation of the original message length (in bits) is appended.
    ///
    /// # Arguments
    ///
    /// * `message` - A string slice containing the message to be padded.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the message after the initial padding, ready for further SHA-256 processing.
    ///
    /// # Examples
    ///
    /// ```
    ///  use sha_256::preprocess::preprocess::initial_sha256_padding;
    ///
    /// let message = "Hello";
    /// let padded = initial_sha256_padding(message);
    /// ```
    pub fn initial_sha256_padding(message: &str) -> Vec<u8> {
        let mut buffer = message.as_bytes().to_vec();
        buffer.push(0x80); // Append 1 bit (0x80 in byte form)

        // Calculate how many zero bytes we need to add so
        // that the current length is congruent to 448 mod 512
        let zero_bytes_to_add = (56 - (buffer.len() % 64)) % 64;

        // Add the required zero bytes
        buffer.extend(vec![0u8; zero_bytes_to_add]);

        // Append the original length of the message, in bits, as a 64-bit big-endian value
        let original_bit_len = (message.len() as u64) * 8; // convert byte length to bit length
        buffer.extend(original_bit_len.to_be_bytes().iter());

        buffer
    }

    /// Splits the padded message into blocks suitable for SHA-256 processing.
    ///
    /// The message, after padding, is divided into multiple 512-bit blocks.
    /// Each 512-bit block is further divided into sixteen 32-bit word blocks.
    ///
    /// # Arguments
    ///
    /// * `msg_pad` - A `Vec<u8>` containing the message after SHA-256 padding.
    ///
    /// # Returns
    ///
    /// A `Vec<Vec<u8>>` where the outer vector contains 512-bit blocks, and each inner vector represents a 32-bit word block.
    ///
    /// # Notes
    ///
    /// It's assumed that the constants `BLOCK_SIZE` and `CHUNK_SIZE` are set to 64 and 4 respectively to align with SHA-256 specifications.
    fn generate_message_blocks(msg_pad: Vec<u8>) -> Vec<Vec<Vec<u8>>> {
        msg_pad
            .chunks(BLOCK_SIZE)
            .map(|block| {
                block
                    .chunks(CHUNK_SIZE)
                    .map(|chunk| chunk.to_vec())
                    .collect()
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const MESSAGE: &str = "hello world";

        #[test]
        fn pad_message() {
            let padded_msg = initial_sha256_padding(MESSAGE);
            assert_eq!(padded_msg.len(), 64);
        }

        #[test]
        fn process_message() {
            let padded_msg = initial_sha256_padding(MESSAGE);

            assert_eq!(padded_msg.len(), 64);

            let msg_blocks = generate_message_blocks(padded_msg);

            for msg_block in msg_blocks {
                assert_eq!(msg_block.len(), 16);

                for block in msg_block {
                    assert_eq!(block.len(), 4);
                }
            }
        }
    }
}
