pub mod aes_ops;
pub mod block_modes;
pub mod definitions;
pub mod pkcs_padding;

mod constants;
mod error;
mod key_schedule;
mod util;

use definitions::*;
use error::AesError;
use key_schedule::*;

#[derive(Debug)]
pub struct AES(KeySchedule);

impl AES {
    pub fn new(pk: &[u8]) -> Result<Self, AesError> {
        Ok(Self(KeySchedule::new(pk)?))
    }

    pub fn encrypt(
        &self,
        mode: BlockMode,
        padding_scheme: PaddingScheme,
        input: &[u8],
    ) -> Result<Vec<[[u8; 4]; 4]>, AesError> {
        let mut enc = match (mode, padding_scheme) {
            (BlockMode::CBC, PaddingScheme::PKSC) => {
                block_modes::CbcEncryptor::new(&self.0, pkcs_padding::PkcsPadding)?
            }
        };

        let cipher_bytes = enc.encrypt(input)?;
        Ok(cipher_bytes)
    }
}
