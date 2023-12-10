use rand::{rngs::OsRng, RngCore};

use super::{
    aes_ops::AesOps,
    definitions::{AesEncryptor, PaddingProcessor},
    error::AesError,
    key_schedule::KeySchedule,
    pkcs_padding::PkcsPadding,
    util::*,
};

pub struct CbcEncryptor {
    pub state: Option<Vec<u8>>,
    pub padding_processor: Box<dyn PaddingProcessor>,
    pub iv: [[u8; 4]; 4],
    keys: KeySchedule,
}

impl CbcEncryptor {
    /// Generates a 16-byte initialization vector (IV) for AES encryption.
    ///
    /// This function uses a cryptographically secure random number generator (OsRng)
    /// to fill a 16-byte array with random data, which serves as the IV.
    ///
    /// Returns:
    /// A 16-byte array `[u8; 16]` representing the IV.
    fn gen_iv() -> [u8; 16] {
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);

        iv
    }

    /// Creates a new instance of an AES encryption structure with CBC mode and padding.
    ///
    /// Parameters:
    /// * `pk`: A byte slice representing the encryption key.
    /// * `padding_processor`: An instance of a type that implements `PaddingProcessor`.
    ///   This type must have a `'static` lifetime.
    ///
    /// Returns:
    /// A `Result` containing the new instance or an `AesError` on failure.
    ///
    /// The function initializes the key schedule for AES based on `pk`,
    /// sets the initial state and IV, and stores the padding processor.
    pub fn new<T: PaddingProcessor + 'static>(
        pk: &[u8],
        padding_processor: T,
    ) -> Result<Self, AesError> {
        Ok(Self {
            keys: KeySchedule::new(pk)?,
            state: None,
            iv: gen_matrix(&Self::gen_iv()),
            padding_processor: Box::new(padding_processor),
        })
    }
}

impl AesEncryptor for CbcEncryptor {
    /// Encrypts a message using AES with CBC mode and PKCS padding.
    ///
    /// This function encrypts the given message using the AES encryption algorithm in CBC mode.
    /// PKCS padding is applied to the message to ensure proper block sizing.
    ///
    /// # Arguments
    /// * `message` - A slice of bytes representing the plaintext message to be encrypted.
    ///
    /// # Returns
    /// A `Result` containing a vector of encrypted 4x4 byte matrices (`Vec<[[u8; 4]; 4]>`)
    /// on success, or an `AesError` on failure.
    fn encrypt(&mut self, message: &[u8]) -> Result<Vec<[[u8; 4]; 4]>, AesError> {
        // Convert the message to a byte vector and apply PKCS padding
        let mut plain_bytes = message.to_vec();
        PkcsPadding.pad_input(&mut plain_bytes);

        // Chunk the padded message into 4x4 byte matrices
        let input_blocks = chunk_bytes_into_4x4_matrices(&plain_bytes);

        // Initialize the working state by XORing the first block with the IV
        let mut working_state = xor_matrices(input_blocks[0], self.iv);

        let mut encrypted_blocks = Vec::with_capacity(input_blocks.len());

        for block in input_blocks {
            AesOps::encrypt(&mut working_state, &self.keys);
            encrypted_blocks.push(working_state);
            working_state = xor_matrices(working_state, block);
        }

        Ok(encrypted_blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INPUT: [u8; 16] = [
        0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255,
    ];

    const PK: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    const IV: [u8; 16] = [
        102, 71, 120, 83, 87, 100, 53, 57, 65, 89, 100, 105, 81, 88, 90, 83,
    ];

    #[test]
    fn test_cbc_encryption() {
        let mut cbc_ops = CbcEncryptor::new(&PK, PkcsPadding).unwrap();
        cbc_ops.iv =  gen_matrix(&IV);

        let start_cipher_bytes: Vec<[[u8; 4]; 4]> = vec![[
            [59, 67, 136, 134],
            [79, 78, 189, 114],
            [137, 150, 207, 148],
            [186, 117, 130, 178],
        ]];

        let result = cbc_ops.encrypt(&INPUT).unwrap();
        assert!(result.as_slice().starts_with(&start_cipher_bytes));
    }
}
