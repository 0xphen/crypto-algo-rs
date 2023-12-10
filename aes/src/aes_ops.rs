use super::{
    constants::{
        AES_INVERSE_S_BOX, AES_S_BOX, INVERSE_TRANSFORMATION_MATRIX, TRANSFORMATION_MATRIX,
    },
    key_schedule::KeySchedule,
    util::{galois_mul, xor_matrices},
};

pub struct AesOps;

impl AesOps {
    /// Performs AES encryption on the given state.
    ///
    /// The `state` is a mutable reference to a vector of 4-byte arrays,
    /// which is encrypted using the provided key schedule. The encryption
    /// modifies the `state` in place, resulting in the ciphertext.
    ///
    /// The AES encryption process consists of:
    /// - An initial AddRoundKey step.
    /// - Several rounds (number specified by `keys.rounds`) of:
    ///   - SubBytes: A non-linear substitution step.
    ///   - ShiftRows: A transposition step.
    ///   - MixColumns: A mixing operation applied to each column.
    ///   - AddRoundKey: Combined with a round key derived from the encryption key.
    /// - A final round that includes SubBytes, ShiftRows, and AddRoundKey,
    ///   but omits the MixColumns step.
    ///
    /// # Arguments
    /// * `state` - A mutable reference to the AES state to be encrypted.
    /// * `keys` - A reference to the `KeySchedule` used for the encryption.
    ///
    /// # Notes
    /// The final encrypted state, or ciphertext, is stored in the `state`
    /// after the completion of this method. As the encryption is done in place,
    /// the input `state` is overwritten with the encrypted data.
    pub fn encrypt(state: &mut [[u8; 4]; 4], keys: &KeySchedule) {
        let rounds = keys.rounds;
        // Add initial round key
        Self::add_round_key(state, keys.round_key(0));

        // Main encryption rounds
        for round in 1..(rounds) {
            Self::sub_bytes(state, AES_S_BOX);
            Self::shift_rows(state);
            Self::mix_columns(state, TRANSFORMATION_MATRIX);
            Self::add_round_key(state, keys.round_key(round as usize));
        }

        //Final round without mixing columns
        Self::sub_bytes(state, AES_S_BOX);
        Self::shift_rows(state);
        Self::add_round_key(state, keys.round_key(rounds as usize));
    }

    pub fn decrypt(cipher_bytes: &mut [[u8; 4]; 4], keys: &KeySchedule) {
        let rounds = keys.rounds;

        Self::add_round_key(cipher_bytes, keys.round_key(rounds as usize));

        for round in (1..(rounds)).rev() {
            Self::inv_shift_rows(cipher_bytes);
            Self::sub_bytes(cipher_bytes, AES_INVERSE_S_BOX);
            Self::add_round_key(cipher_bytes, keys.round_key(round as usize));
            Self::mix_columns(cipher_bytes, INVERSE_TRANSFORMATION_MATRIX);
        }

        Self::inv_shift_rows(cipher_bytes);
        Self::sub_bytes(cipher_bytes, AES_INVERSE_S_BOX);
        Self::add_round_key(cipher_bytes, keys.round_key(0));
    }

    /// Performs the AddRoundKey step, a crucial part of the AES encryption algorithm.
    ///
    /// This method XORs each byte of the AES state with the corresponding byte of the given round key.
    ///
    /// # Arguments
    /// * `key` - The round key to be XORed with the AES state.
    fn add_round_key(state: &mut [[u8; 4]; 4], key: [[u8; 4]; 4]) {
        *state = xor_matrices(*state, key);
    }

    /// Performs the SubBytes or InvSubBytes transformation on the AES state.
    ///
    /// This function executes a non-linear byte substitution step where each byte
    /// in the state is replaced with another according to the provided lookup table (S-box).
    /// This lookup table can be either the standard S-box for encryption or the inverse S-box
    /// for decryption, allowing this function to be used for both SubBytes in encryption
    /// and InvSubBytes in decryption.
    ///
    /// # Arguments
    /// * `state` - A mutable reference to the 4x4 state matrix.
    /// * `s_box` - The S-box used for the transformation, either standard or inverse.
    fn sub_bytes(state: &mut [[u8; 4]; 4], s_box: [u8; 256]) {
        // Iterate over each byte of the state matrix
        for (i, row) in state.iter_mut().enumerate() {
            for (j, e) in row.iter_mut().enumerate() {
                // Apply the S-box transformation and store in `new_state`
                *e = s_box[*e as usize];
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
    fn shift_rows(state: &mut [[u8; 4]; 4]) {
        // Temporary variable to hold the values for row shifting
        let mut temp: [u8; 4] = [0; 4];

        for i in 1..4 {
            for j in 0..4 {
                // Store the shifted row in a temporary variable
                temp[j] = state[(j + i) % 4][i];
            }
            for j in 0..4 {
                // Update the state with the shifted values
                state[j][i] = temp[j];
            }
        }
    }

    /// Performs the inverse shift rows step in AES decryption.
    ///
    /// Each row of the state is shifted cyclically to the right.
    /// The first row remains unchanged, the second row is shifted by one position,
    /// the third row by two positions, and the fourth row by three positions.
    ///
    /// # Arguments
    /// * `state` - A mutable reference to the 4x4 state matrix.
    fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
        let mut temp: [u8; 4];

        // Second row: shift one position to the right
        temp = [state[3][1], state[0][1], state[1][1], state[2][1]];
        for j in 0..4 {
            state[j][1] = temp[j];
        }

        // Third row: shift two positions to the right
        temp = [state[2][2], state[3][2], state[0][2], state[1][2]];
        for j in 0..4 {
            state[j][2] = temp[j];
        }

        // Fourth row: shift three positions to the right
        temp = [state[1][3], state[2][3], state[3][3], state[0][3]];
        for j in 0..4 {
            state[j][3] = temp[j];
        }
    }

    /// Performs the MixColumns or InvMixColumns transformation on the AES state.
    ///
    /// This function applies either the MixColumns or InvMixColumns step to each column
    /// of the AES state matrix, depending on the provided transformation matrix.
    /// It uses Galois Field multiplication (`galois_mul`) for the transformation.
    ///
    /// The transformation matrix should be the standard matrix for MixColumns in AES encryption,
    /// or the inverse matrix for InvMixColumns in AES decryption.
    ///
    /// # Arguments
    /// * `state` - A mutable reference to the 4x4 state matrix.
    /// * `transformation_matrix` - The matrix used for the transformation, either for
    ///   MixColumns or InvMixColumns.
    fn mix_columns(state: &mut [[u8; 4]; 4], transformation_matrix: [[u8; 4]; 4]) {
        for col in 0..4 {
            // Temporary storage for the column being processed
            let mut temp_column = [0u8; 4];

            // Transform the current column using Galois Field multiplication
            for i in 0..4 {
                temp_column[i] = galois_mul(transformation_matrix[i][0], state[col][0])
                    ^ galois_mul(transformation_matrix[i][1], state[col][1])
                    ^ galois_mul(transformation_matrix[i][2], state[col][2])
                    ^ galois_mul(transformation_matrix[i][3], state[col][3]);
            }

            // Update the state matrix with the transformed column
            for i in 0..4 {
                state[col][i] = temp_column[i];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_ops_encrypt_decrypt_test() {
        let mut state: [[u8; 4]; 4] = [
            [0, 17, 34, 51],
            [68, 85, 102, 119],
            [136, 153, 170, 187],
            [204, 221, 238, 255],
        ];

        let key_schedule =
            KeySchedule::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]).unwrap();

        AesOps::encrypt(&mut state, &key_schedule);
        assert_eq!(
            state,
            [
                [105, 196, 224, 216],
                [106, 123, 4, 48],
                [216, 205, 183, 128],
                [112, 180, 197, 90]
            ]
        );

        AesOps::decrypt(&mut state, &key_schedule);
        assert_eq!(
            state,
            [
                [0, 17, 34, 51],
                [68, 85, 102, 119],
                [136, 153, 170, 187],
                [204, 221, 238, 255]
            ]
        );
    }

    #[test]
    fn one_round_encryption_test() {
        let mut state: [[u8; 4]; 4] = [
            [0, 17, 34, 51],
            [68, 85, 102, 119],
            [136, 153, 170, 187],
            [204, 221, 238, 255],
        ];

        let key_schedule =
            KeySchedule::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]).unwrap();

        AesOps::add_round_key(&mut state, key_schedule.round_key(0));
        assert_eq!(
            state,
            [
                [0, 16, 32, 48],
                [64, 80, 96, 112],
                [128, 144, 160, 176],
                [192, 208, 224, 240]
            ]
        );

        AesOps::sub_bytes(&mut state, AES_S_BOX);
        assert_eq!(
            state,
            [
                [99, 202, 183, 4],
                [9, 83, 208, 81],
                [205, 96, 224, 231],
                [186, 112, 225, 140]
            ]
        );

        AesOps::shift_rows(&mut state);
        assert_eq!(
            state,
            [
                [99, 83, 224, 140],
                [9, 96, 225, 4],
                [205, 112, 183, 81],
                [186, 202, 208, 231]
            ]
        );

        AesOps::mix_columns(&mut state, TRANSFORMATION_MATRIX);
        assert_eq!(
            state,
            [
                [95, 114, 100, 21],
                [87, 245, 188, 146],
                [247, 190, 59, 41],
                [29, 185, 249, 26]
            ]
        );
    }

    #[test]
    fn one_round_decryption_test() {
        let key_schedule =
            KeySchedule::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]).unwrap();

        let mut state: [[u8; 4]; 4] = [
            [105, 196, 224, 216],
            [106, 123, 4, 48],
            [216, 205, 183, 128],
            [112, 180, 197, 90],
        ];

        AesOps::add_round_key(&mut state, key_schedule.round_key(10));
        assert_eq!(
            state,
            [
                [122, 213, 253, 167],
                [137, 239, 78, 39],
                [43, 202, 16, 11],
                [61, 159, 245, 159]
            ]
        );

        AesOps::inv_shift_rows(&mut state);
        assert_eq!(
            state,
            [
                [122, 159, 16, 39],
                [137, 213, 245, 11],
                [43, 239, 253, 159],
                [61, 202, 78, 167]
            ]
        );

        AesOps::sub_bytes(&mut state, AES_INVERSE_S_BOX);
        assert_eq!(
            state,
            [
                [189, 110, 124, 61],
                [242, 181, 119, 158],
                [11, 97, 33, 110],
                [139, 16, 182, 137]
            ]
        );

        AesOps::mix_columns(&mut state, TRANSFORMATION_MATRIX);

        AesOps::mix_columns(&mut state, INVERSE_TRANSFORMATION_MATRIX);
        assert_eq!(
            state,
            [
                [189, 110, 124, 61],
                [242, 181, 119, 158],
                [11, 97, 33, 110],
                [139, 16, 182, 137]
            ]
        );
    }
}
