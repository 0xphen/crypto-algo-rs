mod constants;
mod error;
mod key_schedule;
mod utils;

use constants::*;
use error::AesError;
use key_schedule::*;
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

    /// Initializes the state
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

    /// Performs the SubBytes transformation on the AES state.
    /// This is a non-linear byte substitution step where each byte is replaced
    /// with another according to a lookup table (S-box).
    /// It mutates the current AES state by updating each byte with its substituted value.
    fn sub_bytes(&mut self) {
        // Temporary state to store the transformed bytes
        let mut new_state: [[u8; 4]; 4] = [[0; 4]; 4];

        // Iterate over each byte of the state matrix
        for (i, row) in self.state.iter().enumerate() {
            for (j, &e) in row.iter().enumerate() {
                // Apply the S-box transformation and store in `new_state`
                new_state[j][i] = AES_S_BOX[e as usize];
            }
        }

        self.state = new_state;
    }

    /// Performs the ShiftRows step in AES encryption.
    /// It leaves the first row unchanged and cyclically shifts the remaining rows to the left
    /// by their row index (1 to 3 positions).
    fn shift_rows(&mut self) {
        let mut new_state = [[0u8; 4]; 4];
        // Copy the first row as is
        new_state[0] = self.state[0];
        // Shift the remaining rows
        for i in 1..=3 {
            new_state[i] = rotate_left(&self.state[i], i);
        }

        self.state = new_state;
    }

    /// Applies the MixColumns transformation to the AES state matrix.
    /// This transformation is a key step in the AES encryption process, where each column
    /// of the state matrix is mixed to produce a new state. It involves performing
    /// Galois Field multiplication of predefined matrix values with the current state.
    fn mix_columns(&mut self) {
        let mut new_state: [[u8; 4]; 4] = [[0u8; 4]; 4];

        for r in 0..4 {
            for c in 0..4 {
                // Compute the new value for each cell in the new state matrix.
                // This is done by XORing the results of Galois Field multiplication
                // of each element in the predefined matrix with the corresponding
                // element in the current state matrix.
                new_state[r][c] = (0..4).fold(0, |acc, i| {
                    acc ^ galois_mul(PRE_DEFINED_MATRIX[r][i], self.state[i][c])
                })
            }
        }

        self.state = new_state;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use lazy_static::lazy_static;
    use serial_test::serial;

    use std::sync::Mutex;

    const INPUT: [u8; 16] = [
        40, 106, 74, 8, 45, 243, 78, 144, 243, 134, 144, 229, 196, 37, 167, 70,
    ];
    const PK: [u8; 16] = [
        83, 165, 133, 154, 74, 213, 132, 2, 117, 219, 45, 35, 95, 132, 207, 167,
    ];

    lazy_static! {
        static ref AES_INSTANCE: Mutex<AES> = Mutex::new(AES::new(&PK, &INPUT).unwrap());
    }

    #[test]
    #[serial]
    fn test_substitution() {
        let mut aes_guard = AES_INSTANCE.lock().unwrap();
        let aes = &mut *aes_guard;

        aes.sub_bytes();

        assert_eq!(
            aes.state,
            [
                [52, 2, 214, 48],
                [216, 13, 47, 96],
                [13, 68, 96, 217],
                [28, 63, 92, 90]
            ]
        );
    }

    #[test]
    #[serial]
    fn test_shift_rows() {
        let mut aes_guard = AES_INSTANCE.lock().unwrap();
        aes_guard.shift_rows();

        assert_eq!(
            aes_guard.state,
            [
                [52, 2, 214, 48],
                [13, 47, 96, 216],
                [96, 217, 13, 68],
                [90, 28, 63, 92]
            ]
        );
    }

    #[test]
    #[serial]
    fn test_mix_columns() {
        let mut aes_guard = AES_INSTANCE.lock().unwrap();
        aes_guard.mix_columns();

        assert_eq!(
            aes_guard.state,
            [
                [71, 64, 163, 76],
                [55, 212, 112, 159],
                [148, 228, 58, 66],
                [237, 165, 166, 188]
            ]
        );
    }
}
