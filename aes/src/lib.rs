mod error;
mod key_schedule;
mod s_box;
mod utils;

use rayon::prelude::*;

use error::AesError;
use key_schedule::*;
use s_box::AES_S_BOX;
use utils::*;

#[derive(Debug)]
pub struct AES {
    state: [[u8; 4]; 4],
    key_schedule: KeySchedule,
}

impl AES {
    pub fn new(pk: &[u8], bytes: &[u8]) -> Result<Self, AesError> {
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_e| AesError::InvalidBitsSize(12))?;

        Ok(Self {
            state: Self::init_state(&bytes),
            key_schedule: KeySchedule::new(pk)?,
        })
    }

    fn init_state(bytes: &[u8; 16]) -> [[u8; 4]; 4] {
        let mut state = [[0; 4]; 4];

        for (i, chunk) in bytes.chunks(4).enumerate() {
            for (j, &byte) in chunk.iter().enumerate() {
                state[j][i] = byte;
            }
        }

        state
    }

    fn add_round_key(state: [[u8; 4]; 4], key: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
        xor_matrices(state, key)
    }

    fn sub_bytes(&self) -> [[u8; 4]; 4] {
        // Temporary state to store the transformed bytes
        let mut new_state: [[u8; 4]; 4] = [[0; 4]; 4];

        // Iterate over each byte of the state matrix
        for (i, row) in self.state.iter().enumerate() {
            for (j, &e) in row.iter().enumerate() {
                // Apply the S-box transformation and store in new_state
                new_state[j][i] = AES_S_BOX[e as usize];
            }
        }

        new_state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INPUT: [u8; 16] = [
        40, 106, 74, 8, 45, 243, 78, 144, 243, 134, 144, 229, 196, 37, 167, 70,
    ];
    const PK: [u8; 16] = [
        83, 165, 133, 154, 74, 213, 132, 2, 117, 219, 45, 35, 95, 132, 207, 167,
    ];

    #[test]
    fn substitution() {
        let aes = AES::new(&PK, &INPUT).unwrap();
        let new_state = aes.sub_bytes();

        assert_eq!(
            new_state,
            [
                [52, 2, 214, 48],
                [216, 13, 47, 96],
                [13, 68, 96, 217],
                [28, 63, 92, 90]
            ]
        );
    }
}
