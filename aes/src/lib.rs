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
            state: gen_matrix(&bytes),
            key_schedule: KeySchedule::new(pk)?,
        })
    }

    fn add_round_key(&mut self, key: [[u8; 4]; 4]) {
        self.state = xor_matrices(self.state, key)
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

    const INPUT: [u8; 16] = [
        184, 186, 199, 73, 3, 159, 73, 223, 184, 186, 199, 73, 3, 159, 73, 223,
    ];

    const PK: [u8; 16] = [
        144, 151, 52, 80, 105, 108, 207, 250, 242, 244, 87, 51, 11, 15, 172, 153,
    ];

    #[test]
    fn aes_encryption() {
        let mut aes = AES::new(&PK, &INPUT).unwrap();
    }

    // #[test]
    // fn test_add_round_key() {
    //     let mut aes = AES::new(&PK, &INPUT).unwrap();
    //     aes.add_round_key();

    //     assert_eq!(
    //         aes.state,
    //         [
    //             [52, 2, 214, 48],
    //             [216, 13, 47, 96],
    //             [13, 68, 96, 217],
    //             [28, 63, 92, 90]
    //         ]
    //     );
    // }

    #[test]
    fn test_substitution() {
        let mut aes = AES::new(&PK, &INPUT).unwrap();
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
    fn test_shift_rows() {
        let mut aes = AES::new(&PK, &INPUT).unwrap();
        aes.shift_rows();

        assert_eq!(
            aes.state,
            [
                [40, 45, 243, 196],
                [243, 134, 37, 106],
                [144, 167, 74, 78],
                [70, 8, 144, 229]
            ]
        );
    }
}

// [0, 1, 2, 3],
// [4, 5, 6, 7],
// [8, 9, 10, 11],
// [12, 13, 14, 15]

// G function input: [3, 7, 11, 15], 1
// G function output:  [7, 11, 15, 3] -> [197, 43, 118, 123]
// COL_1: [196, 43, 118, 123] ^ [0, 4, 8, 12] = [196, 47, 126, 119]
// COL_2: [196, 47, 126, 119] ^ [1,5,9,13] = [197, 42, 119, 122]
// COL_3: [197, 42, 119, 122] ^ [2,6,10,14] = [199, 44, 125, 116]
// COL_4: [199, 44, 125, 116] ^ [3,7,11,15] = [196, 43, 118, 123]
//
//[[196, 197, 199, 196], [47, 42, 44, 43], [126, 119, 125, 118], [119, 122, 116, 123]]
//
//
//
// [8, 12, 16, 4] => [49, 254, 202, 242]

// 214, 170
