use super::error::AesError;

pub trait AesEncryptor {
    fn encrypt(&mut self, message: &[u8]) -> Result<Vec<[[u8; 4]; 4]>, AesError>;
}

/// Trait for padding processing in cryptographic operations.
pub trait PaddingProcessor {
    /// Adds padding to the given input buffer.
    ///
    /// # Arguments
    /// * `input_buffer` - A mutable reference to a vector of bytes representing the input data.
    fn pad_input(&self, input_buffer: &mut Vec<u8>);

    /// Removes padding from the given output buffer.
    ///
    /// # Arguments
    /// * `output_buffer` - A mutable reference to a vector of bytes representing the output data.
    fn strip_output(&self, output_buffer: &mut Vec<u8>);
}

/// Enum representing different padding schemes.
pub enum PaddingScheme {
    /// Represents the PKSC padding scheme.
    PKSC,
}
