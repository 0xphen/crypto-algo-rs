use super::error::AesError;

const AES_KEY_SIZE_128: usize = 128 / 8;
const AES_KEY_SIZE_192: usize = 192 / 8;
const AES_KEY_SIZE_256: usize = 256 / 8;

pub struct KeySchedule {
    key: Vec<u8>,
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
        match pk.len() {
            AES_KEY_SIZE_128 | AES_KEY_SIZE_192 | AES_KEY_SIZE_256 => Ok(Self { key: pk.to_vec() }),
            _ => Err(AesError::InvalidKeySize(pk.len())),
        }
    }
}
