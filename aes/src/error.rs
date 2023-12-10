use thiserror::Error;

#[derive(Error, Debug)]
pub enum AesError {
    #[error("Invalid key size of `{0}`")]
    InvalidKeySize(usize),

    #[error("Invalid bits size. Expected 128 got `{0}`")]
    InvalidBitsSize(usize),

    #[error("Failed to convert matrix to fixed size")]
    KeyMatrixConversionError,

    #[error("Failed to generate IV")]
    IVGenerationError,

    #[error("Failed to parse slice to matrix: {0}")]
    FailedToParseSliceToMatrix(String),
}
