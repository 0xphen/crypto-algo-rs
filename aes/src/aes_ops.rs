use super::{
    constants::{AES_S_BOX, TRANSFORMATION_MATRIX},
    key_schedule::KeySchedule,
    util::*,
};

/// Structure for performing AES encryption operations.
///
/// This struct is used internally by various AES encryption modes to encrypt plaintext.
/// It holds references to the encryption state and key schedule, essential for the
/// AES encryption and decryption processes.
///
/// The `state` field is a mutable reference to the AES state, represented as a vector
/// of 4-byte arrays, which is manipulated during the encryption process.
///
/// The `keys` field is a reference to the `KeySchedule`, containing the necessary
/// keys derived from the original encryption key for the AES algorithm stages.
pub struct AesOps<'s, 'k> {
    // Mutable reference to the AES state, represented as a vector of 4-byte arrays.
    state: &'s mut Vec<[u8; 4]>,

    // Reference to the key schedule, essential for AES encryption and decryption processes.
    keys: &'k KeySchedule,
}

impl<'s, 'k> AesOps<'s, 'k> {
    /// Constructs a new `AesOps` instance for AES operations.
    ///
    /// # Arguments
    /// * `state` - Mutable reference to the initial AES state.
    /// * `keys` - Reference to a precomputed `KeySchedule`.
    pub fn new(state: &'s mut Vec<[u8; 4]>, keys: &'k KeySchedule) -> Self {
        Self { state, keys }
    }

    /// Performs AES encryption on the state.
    ///
    /// This method executes the complete AES encryption process on the `state`.
    /// The encryption is performed in place, meaning the `state` is directly modified
    /// to represent the encrypted data (cipher text) after the method completes.
    ///
    /// The process involves:
    /// - An initial AddRoundKey step.
    /// - Several rounds (determined by the length of the key) consisting of
    ///   SubBytes, ShiftRows, MixColumns, and AddRoundKey.
    /// - A final round that includes SubBytes, ShiftRows, and AddRoundKey, but omits MixColumns.
    ///
    /// # Note
    /// The encrypted data, or cipher text, is stored in the `state` field of the struct
    /// upon completion of this method. The `state` is thus modified to contain the
    /// result of the AES encryption.
    pub fn encrypt(&mut self) {
        let rounds = self.keys.rounds;
        // Add initial round key
        self.add_round_key(self.keys.round_key(0));

        // Main encryption rounds
        for round in 1..(rounds) {
            self.sub_bytes();
            self.shift_rows();
            self.mix_columns();
            self.add_round_key(self.keys.round_key(round as usize));
        }

        //Final round without mixing columns
        self.sub_bytes();
        self.shift_rows();
        self.add_round_key(self.keys.round_key(rounds as usize));
    }

    /// Performs the AddRoundKey step, a crucial part of the AES encryption algorithm.
    ///
    /// This method XORs each byte of the AES state with the corresponding byte of the given round key.
    ///
    /// # Arguments
    /// * `key` - The round key to be XORed with the AES state.
    fn add_round_key(&mut self, key: [[u8; 4]; 4]) {
        for ((row_a, row_b)) in self.state.iter_mut().zip(key.iter()) {
            for ((val_a, val_b)) in row_a.iter_mut().zip(row_b.iter()) {
                *val_a ^= val_b;
            }
        }
    }

    /// Performs the SubBytes transformation on the AES state.
    /// This is a non-linear byte substitution step where each byte is replaced
    /// with another according to a lookup table (S-box).
    /// It mutates the current AES state by updating each byte with its substituted value.
    fn sub_bytes(&mut self) {
        // Iterate over each byte of the state matrix
        for (i, row) in self.state.iter_mut().enumerate() {
            for (j, e) in row.iter_mut().enumerate() {
                // Apply the S-box transformation and store in `new_state`
                *e = AES_S_BOX[*e as usize];
            }
        }
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

    /// Performs the MixColumns transformation on the AES state.
    ///
    /// This function applies the MixColumns step to each column of the AES state matrix.
    /// It uses the Galois Field multiplication (`galois_mul`) for the transformation.
    ///
    /// # Arguments
    /// * `&mut self` - A mutable reference to the AES structure, containing the state matrix.
    fn mix_columns(&mut self) {
        for col in 0..4 {
            // Temporary storage for the column being processed
            let mut temp_column = [0u8; 4];

            // Transform the current column using Galois Field multiplication
            for i in 0..4 {
                temp_column[i] = galois_mul(TRANSFORMATION_MATRIX[i][0], self.state[col][0])
                    ^ galois_mul(TRANSFORMATION_MATRIX[i][1], self.state[col][1])
                    ^ galois_mul(TRANSFORMATION_MATRIX[i][2], self.state[col][2])
                    ^ galois_mul(TRANSFORMATION_MATRIX[i][3], self.state[col][3]);
            }

            // Update the state matrix with the transformed column
            for i in 0..4 {
                self.state[col][i] = temp_column[i];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_ops_encrypt_test() {
        let mut state: Vec<[u8; 4]> = vec![
            [0, 17, 34, 51],
            [68, 85, 102, 119],
            [136, 153, 170, 187],
            [204, 221, 238, 255],
        ];

        let key_schedule =
            KeySchedule::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]).unwrap();

        let mut aes_ops = AesOps::new(&mut state, &key_schedule);
        aes_ops.encrypt();

        assert_eq!(
            aes_ops.state,
            &vec![
                [105, 196, 224, 216],
                [106, 123, 4, 48],
                [216, 205, 183, 128],
                [112, 180, 197, 90]
            ]
        );
    }

    #[test]
    fn initial_round_key_and_one_round_test() {
        let mut state: Vec<[u8; 4]> = vec![
            [0, 17, 34, 51],
            [68, 85, 102, 119],
            [136, 153, 170, 187],
            [204, 221, 238, 255],
        ];

        let key_schedule =
            KeySchedule::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]).unwrap();

        let mut aes_ops = AesOps::new(&mut state, &key_schedule);

        aes_ops.add_round_key(aes_ops.keys.round_key(0));
        assert_eq!(
            aes_ops.state,
            &vec![
                [0, 16, 32, 48],
                [64, 80, 96, 112],
                [128, 144, 160, 176],
                [192, 208, 224, 240]
            ]
        );

        aes_ops.sub_bytes();
        assert_eq!(
            aes_ops.state,
            &vec![
                [99, 202, 183, 4],
                [9, 83, 208, 81],
                [205, 96, 224, 231],
                [186, 112, 225, 140]
            ]
        );

        aes_ops.shift_rows();
        assert_eq!(
            aes_ops.state,
            &vec![
                [99, 83, 224, 140],
                [9, 96, 225, 4],
                [205, 112, 183, 81],
                [186, 202, 208, 231]
            ]
        );

        aes_ops.mix_columns();
        assert_eq!(
            aes_ops.state,
            &vec![
                [95, 114, 100, 21],
                [87, 245, 188, 146],
                [247, 190, 59, 41],
                [29, 185, 249, 26]
            ]
        );
    }
}
