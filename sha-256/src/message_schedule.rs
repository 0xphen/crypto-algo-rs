pub mod message_schedule {
    const CHUNK_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 512;

    fn first_schedule(msg_binary: &str) -> Vec<Vec<String>> {
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
        fn get_16_32_bit_words() {
            let n_512_blocks = first_schedule(padded_msg);

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
