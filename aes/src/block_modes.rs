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

// impl AesEncryptor for CbcEncryptor {
//     fn encrypt(&mut self, message: &[u8]) -> Vec<u8> {
//         let mut plain_bytes = message.to_vec();
//         PkcsPadding.pad_input(&mut plain_bytes);

//         let input_block = chunk_bytes_into_quads(&plain_bytes);
//         let mut state = xor_matrix_with_array(&input_block[0..3].to_vec(), self.iv);
//         let mut encrypted_blocks: Vec<[u8; 4]> = vec![[0u8; 4]; input_block.len()];

//         for _ in 1..(input_block.len() / 4) {
//             AesOps::encrypt(&mut state, &self.keys);
//         }

//         todo!();
//     }
// }
