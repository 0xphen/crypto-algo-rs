/// This module parses an input data to its corresponding binary representation.
/// And pads the binary to be a multiple of 512 (for SHA-256). For compactness,
/// we represent the message in hex.
pub mod preprocess {
    pub fn preprocess_message(message: &str) -> String {
        let msg_binary = convert_msg_to_binary(message);
        pad_binary(msg_binary.as_str())
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn preprocess_message() {
            let message = "hello world";
            let msg_to_binary = "0110100001100101011011000110110001101111001000000111011101101111011100100110110001100100";

            let padded_msg = format!("{}{}", msg_to_binary, "1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001011000");

            let binary = convert_msg_to_binary(message);
            assert_eq!(binary, msg_to_binary);

            let padded_binary = pad_binary(&binary);
            assert_eq!(padded_binary, padded_msg);
        }
    }
}
