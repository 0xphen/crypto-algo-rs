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
                new_state[i][j] = AES_S_BOX[e as usize];
            }
        }

        self.state = new_state;
    }

    /// Performs the "ShiftRows" step in the AES encryption process.
    /// This function shifts the rows of the state matrix as per AES specification:
    /// - The first row is not shifted.
    /// - Each subsequent row is shifted to the left by an offset equal to its row index.
    /// - The state matrix is assumed to be column-major, i.e., each inner array represents a column.
    ///
    /// # Arguments
    /// * `&mut self` - A mutable reference to the current instance of the AES struct.
    fn shift_rows(&mut self) {
        // Temporary variable to hold the values for row shifting
        let mut temp: [u8; 4] = [0; 4];

        // Shift rows 1 to 3
        for i in 1..4 {
            for j in 0..4 {
                // Store the shifted row in a temporary variable
                temp[j] = self.state[(j + i) % 4][i];
            }
            for j in 0..4 {
                // Update the state with the shifted values
                self.state[j][i] = temp[j];
            }
        }
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
        0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255,
    ];

    const PK: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    #[test]
    fn aes_encryption() {
        let mut aes = AES::new(&PK, &INPUT).unwrap();

        aes.add_round_key(aes.key_schedule.round_key(0));
        assert_eq!(
            aes.state,
            [
                [0, 16, 32, 48],
                [64, 80, 96, 112],
                [128, 144, 160, 176],
                [192, 208, 224, 240]
            ]
        );

        aes.sub_bytes();
        assert_eq!(
            aes.state,
            [
                [99, 202, 183, 4],
                [9, 83, 208, 81],
                [205, 96, 224, 231],
                [186, 112, 225, 140]
            ]
        );

        aes.shift_rows();
        assert_eq!(
            aes.state,
            [
                [99, 83, 224, 140],
                [9, 96, 225, 4],
                [205, 112, 183, 81],
                [186, 202, 208, 231]
            ]
        );

        // aes.mix_columns();
        // assert_eq!(
        //     aes.state,
        //     [
        //         [95, 114, 100, 21],
        //         [87, 245, 188, 146],
        //         [247, 190, 59, 41],
        //         [29, 185, 249, 26]
        //     ]
        // );
    }
}
