mod error;
mod key_schedule;
mod state;
mod utils;

use error::AesError;
use key_schedule::*;
use state::*;
use utils::*;

pub struct AES {
    state: State,
    key_schedule: KeySchedule,
}

impl AES {
    pub fn new(pk: &[u8], bytes: &[u8]) -> Result<Self, AesError> {
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_e| AesError::InvalidBitsSize(12))?;

        Ok(Self {
            state: State::new(&bytes),
            key_schedule: KeySchedule::new(pk)?,
        })
    }

    fn add_round_key(state: [[u8; 4]; 4], key: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
        xor_matrices_4x4(state, key)
    }
}
