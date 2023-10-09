/// This module performs the preprocessing of a message.
/// Preprocessing involves 3 steps:
/// 1. Padding a message.
/// 2. Parsing the message into message blocks.
/// 3. Setting the initial hash value `H_0`.
pub mod preprocess {
    const BLOCK_SIZE: usize = 64;
    const CHUNK_SIZE: usize = 4;

    #[derive(Debug)]
    /// Represents the result of the preprocessing step.
    pub struct PreprocessResult(pub Vec<[[u8; 4]; 16]>);

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

        return PreprocessResult(preprocessed_msg);
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
        // TODO: Potential error, look into this...
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

    /// Parses a padded message for SHA-256 processing.
    ///
    /// The function divides the message into N blocks of 512 bits each (64 bytes).
    /// Each of these blocks is further parsed into sixteen 32-bit (4 bytes) blocks.
    ///
    /// # Arguments
    /// * `msg_pad` - The padded message to be processed.
    ///
    /// # Returns
    /// A vector of 512-bit blocks, where each block is an array of sixteen 4-byte arrays.
    fn generate_message_blocks(msg_pad: Vec<u8>) -> Vec<[[u8; 4]; 16]> {
        msg_pad
            .chunks(BLOCK_SIZE)
            .map(|block| {
                let mut array_block: [[u8; 4]; 16] = Default::default();

                for (i, chunk) in block.chunks(CHUNK_SIZE).enumerate() {
                    array_block[i] = match chunk {
                        &[a, b, c, d] => [a, b, c, d],
                        _ => panic!("Expected a chunk of size 4!"),
                    };
                }
                array_block
            })
            .collect()
    }

    /// Converts a 32-bit hexadecimal string into a 4-byte array.
    ///
    /// # Arguments
    /// * `h` - A 32-bit hexadecimal string.
    ///
    /// # Returns
    /// A 4-byte array representing the hexadecimal string.
    ///
    /// # Panics
    /// Panics if the input string `h` is not 8 characters long,
    /// or if the string cannot be converted to a byte array.
    pub fn hex_to_byte_array(h: &str) -> [u8; 4] {
        if h.len() != 8 {
            panic!("Constant {:?} has wrong length", h);
        }

        let mut bytes = [0u8; 4];
        for i in 0..4 {
            let start = i * 2;
            let end = start + 2;
            let slice = &h[start..end];
            bytes[i] = u8::from_str_radix(slice, 16).expect("Failed to convert to hexadecimal");
        }

        bytes
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::constants;

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

        #[test]
        fn convert_h() {
            let bytes = hex_to_byte_array(constants::H[0]);
            assert_eq!(bytes, [106, 9, 230, 103]);
        }
    }
}
