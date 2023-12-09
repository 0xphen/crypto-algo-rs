use super::{constants::*, error::AesError, utils::rotate_left};

const AES_KEY_SIZE_128: usize = 128 / 8;
const AES_KEY_SIZE_192: usize = 192 / 8;
const AES_KEY_SIZE_256: usize = 256 / 8;

const ROUNDS_128: u8 = 10;
const ROUNDS_192: u8 = 12;
const ROUNDS_256: u8 = 14;

#[derive(Debug)]
pub struct KeySchedule {
    keys: Vec<[u8; 4]>,
    pub rounds: u8,
}

/// Creates a new `KeySchedule` from the provided key.
///
/// # Arguments
/// * `pk` - A byte slice representing the key.
///
/// # Returns
/// An instance of `KeySchedule` or an error if the key size is invalid.
///
/// # Panics
/// Panics if the key size is not 128, 192, or 256 bits.
impl KeySchedule {
    pub fn new(pk: &[u8]) -> Result<Self, AesError> {
        let pk: [u8; 16] = pk
            .try_into()
            .map_err(|_e| AesError::InvalidKeySize(pk.len()))?;

        let keys = Self::key_expansion(&pk)?;

        match pk.len() {
            AES_KEY_SIZE_128 => Ok(Self {
                keys,
                rounds: ROUNDS_128,
            }),
            AES_KEY_SIZE_192 => Ok(Self {
                keys,
                rounds: ROUNDS_192,
            }),
            AES_KEY_SIZE_256 => Ok(Self {
                keys,
                rounds: ROUNDS_256,
            }),
            _ => Err(AesError::InvalidKeySize(pk.len())),
        }
    }

    /// Retrieves the round key for a specific AES encryption round.
    pub fn round_key(&self, round: usize) -> [[u8; 4]; 4] {
        let mut key: [[u8; 4]; 4] = [[0; 4]; 4];
        let start = round * 4;
        key.copy_from_slice(&self.keys[start..(start + 4)]);

        key
    }

    /// Performs key expansion for AES encryption.
    ///
    /// This function expands an initial key into a series of round keys used
    /// in each round of AES encryption. The key expansion process transforms
    /// the initial key into a larger key matrix suitable for the number of
    /// encryption rounds.
    ///
    /// Args:
    ///     pk: The initial encryption key as a byte slice.
    ///     n: The number of rounds for key expansion. For AES-128, this should be 10.
    ///
    /// Returns:
    ///     A `Vec<[u8; 4]>` representing the expanded key if successful, or
    ///     an `AesError` in case of an error.
    ///
    /// Errors:
    ///     Returns `AesError` if the initial key is too short or if any
    ///     part of the key expansion process fails.
    fn key_expansion(pk: &[u8]) -> Result<Vec<[u8; 4]>, AesError> {
        let mut words: Vec<[u8; 4]> = vec![];

        // Generate the initial words `w0-w3`
        pk.chunks(4).for_each(|chunk| {
            let mut array = [0u8; 4];
            let len = chunk.len().min(4);
            array[..len].copy_from_slice(&chunk[..len]);
            words.push(array);
        });

        for round in 0..10 {
            let previous_key_matrix_slice = &words[words.len().saturating_sub(4)..];

            let previous_key_matrix: [[u8; 4]; 4] = match previous_key_matrix_slice {
                [row0, row1, row2, row3] => [*row0, *row1, *row2, *row3],
                _ => return Err(AesError::KeyMatrixConversionError),
            };

            let new_key_round =
                Self::generate_new_round(&previous_key_matrix, ROUND_CONSTANT_128[round]);

            for row in new_key_round {
                words.push(row);
            }
        }

        Ok(words)
    }

    /// Generates a new round key for AES encryption.
    ///
    /// This function is part of the AES key expansion algorithm for a 128-bit key.
    /// It takes the previous round key and applies a series of transformations
    /// to generate the new round key.
    ///
    /// Args:
    ///     key_matrix: The previous round key, a 4x4 matrix of bytes.
    ///     rc: The round constant for the current round of key expansion.
    ///
    /// Returns:
    ///     A new 4x4 matrix representing the next round key.
    fn generate_new_round(key_matrix: &[[u8; 4]; 4], rc: u8) -> [[u8; 4]; 4] {
        let mut new_key_matrix: [[u8; 4]; 4] = [[0u8; 4]; 4];

        // Apply the g_function to the last column of the previous round key
        let mut array_rc = KeySchedule::g_function(key_matrix[key_matrix.len() - 1], rc);
        for c in 0..4 {
            let mut next_array_rc: [u8; 4] = [0u8; 4];
            // XOR each column of the previous key with the transformed column
            // to create the new round key
            for r in 0..4 {
                new_key_matrix[c][r] = array_rc[r] ^ key_matrix[c][r];
                next_array_rc[r] = new_key_matrix[c][r];
            }

            // Update array_rc for the next iteration
            array_rc = next_array_rc;
        }

        new_key_matrix
    }

    /// Performs the 'g' function of the AES key expansion.
    ///
    /// This function is part of the key expansion routine for AES encryption. It
    /// involves three main steps: rotation, byte substitution using the AES S-Box,
    /// and XORing with a round constant.
    ///
    /// Args:
    ///     word: The 4-byte word to be transformed as part of the key expansion.
    ///     rc: The round constant.
    ///
    /// Returns:
    ///     A new 4-byte word obtained after applying the g function.
    fn g_function(word: [u8; 4], rc: u8) -> [u8; 4] {
        // Rotate `word` left by 1 byte.
        let mut new_word = rotate_left(&word, 1);

        // Perform byte substitution using the AES S-Box.
        // Each byte of `new_word` is replaced with its corresponding value from the AES S-Box.
        for byte in new_word.iter_mut() {
            *byte = AES_S_BOX[*byte as usize];
        }

        // XOR the first byte of the transformed word with the round constant for the current round.
        new_word[0] ^= rc;

        new_word
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g_function() {
        let new_word = KeySchedule::g_function([1, 2, 3, 4], 1);
        assert_eq!(new_word, [118, 123, 242, 124]);
    }

    #[test]
    fn test_key_expansion() {
        let pk: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let key_schedule = KeySchedule::new(&pk).unwrap();
        assert_eq!(
            key_schedule.keys,
            [
                [0, 1, 2, 3],
                [4, 5, 6, 7],
                [8, 9, 10, 11],
                [12, 13, 14, 15],
                [214, 170, 116, 253],
                [210, 175, 114, 250],
                [218, 166, 120, 241],
                [214, 171, 118, 254],
                [182, 146, 207, 11],
                [100, 61, 189, 241],
                [190, 155, 197, 0],
                [104, 48, 179, 254],
                [182, 255, 116, 78],
                [210, 194, 201, 191],
                [108, 89, 12, 191],
                [4, 105, 191, 65],
                [71, 247, 247, 188],
                [149, 53, 62, 3],
                [249, 108, 50, 188],
                [253, 5, 141, 253],
                [60, 170, 163, 232],
                [169, 159, 157, 235],
                [80, 243, 175, 87],
                [173, 246, 34, 170],
                [94, 57, 15, 125],
                [247, 166, 146, 150],
                [167, 85, 61, 193],
                [10, 163, 31, 107],
                [20, 249, 112, 26],
                [227, 95, 226, 140],
                [68, 10, 223, 77],
                [78, 169, 192, 38],
                [71, 67, 135, 53],
                [164, 28, 101, 185],
                [224, 22, 186, 244],
                [174, 191, 122, 210],
                [84, 153, 50, 209],
                [240, 133, 87, 104],
                [16, 147, 237, 156],
                [190, 44, 151, 78],
                [19, 17, 29, 127],
                [227, 148, 74, 23],
                [243, 7, 167, 139],
                [77, 43, 48, 197]
            ]
        );
    }
}
