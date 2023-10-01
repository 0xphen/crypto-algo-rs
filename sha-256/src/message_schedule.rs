pub mod message_schedule {
    const CHUNK_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 512;

    /// The message and its padding is parsed into N 512-bit blocks.
    /// And each 512-bit block is further parsed into sixteen 32-bit blocks.
    ///
    /// # Arguments
    /// * `msg_binary` - The padded binary message
    ///
    /// # Returns
    /// A nested array
    pub fn generate_message_blocks(msg_binary: &str) -> Vec<Vec<String>> {
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

        const padded_msg: &str = "01101000011001010110110001101100011011110010000001110111011011110111001001101100011001001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001011000";

        #[test]
        fn parse_blocks() {
            let n_512_blocks = generate_message_blocks(padded_msg);

            assert_eq!(n_512_blocks.len(), padded_msg.len() / 512);

            for block in n_512_blocks {
                assert_eq!(block.len(), 16);
                for word in block {
                    assert_eq!(word.len(), 32);
                }
            }
        }
    }
}

pub mod init_hash {
    use crate::preprocess::preprocess::{preprocess_message, Format::HEX};

    /// An initial hash value is preprocessed. The hash value
    /// is first converted from hex to its binary representation,
    /// then padded based on SHA-256 padding rules.
    pub fn init_hash(hex_str: &str) -> String {
        preprocess_message(hex_str, HEX)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use crate::{constants, message_schedule::message_schedule};

        #[test]
        fn initialize_h_0() {
            let expected_h_0_padded_msg = "01101010000010011110011001100111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000";

            let padded_hash = init_hash(constants::H_0);
            assert_eq!(padded_hash, expected_h_0_padded_msg);

            let parsed_hash = message_schedule::generate_message_blocks(&padded_hash);
            println!("SEE: {:?}", parsed_hash);
        }
    }
}
