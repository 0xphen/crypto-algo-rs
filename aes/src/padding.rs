use rayon::iter::repeat;

use super::definitions::PaddingScheme;

const BLOCK_SIZE: usize = 16;

/// PKCS padding mode for ECB encryption
///
/// This struct implements the PKCS#7 padding scheme, used in block cipher encryption
/// to ensure the plaintext is a multiple of the block size.
#[derive(Clone, Copy)]
pub struct PkcsPadding;

impl PaddingScheme for PkcsPadding {
    /// Adds PKCS#7 padding to the input buffer.
    ///
    /// This method calculates the necessary number of padding bytes and appends
    /// them to the input buffer. Each padding byte has a value equal to the
    /// number of padding bytes.
    ///
    /// # Arguments
    /// * `input_buffer` - A mutable reference to a Vec<u8> representing the plaintext.
    fn pad_input(input_buffer: &mut Vec<u8>) {
        let pad_size = BLOCK_SIZE - (input_buffer.len() % BLOCK_SIZE);
        let padding: Vec<u8> = std::iter::repeat(pad_size as u8).take(pad_size).collect();
        input_buffer.extend(padding);
    }

    /// Removes PKCS#7 padding from the output buffer.
    ///
    /// This method validates and strips the padding bytes from the output buffer.
    /// It panics if the output buffer's length is not a multiple of BLOCK_SIZE or
    /// if the padding is incorrect.
    ///
    /// # Arguments
    /// * `output_buffer` - A mutable reference to a Vec<u8> representing the padded plaintext.
    ///
    /// # Panics
    /// Panics if the length of `output_buffer` is not a multiple of `BLOCK_SIZE`,
    /// or if the padding bytes are incorrect.
    fn strip_output(output_buffer: &mut Vec<u8>) {
        if output_buffer.len() % BLOCK_SIZE != 0 {
            panic!(
                "Invalid output size: length is not a multiple of {}.",
                BLOCK_SIZE
            );
        }

        if let Some(&pad_size) = output_buffer.last() {
            if pad_size as usize > BLOCK_SIZE || pad_size == 0 {
                panic!("Invalid padding: incorrect padding size.");
            }
            let expected_padding = vec![pad_size; pad_size as usize];
            if output_buffer.ends_with(&expected_padding) {
                output_buffer.truncate(output_buffer.len() - pad_size as usize);
            } else {
                panic!("Invalid padding: incorrect padding bytes.");
            }
        } else {
            panic!("Invalid padding: empty output buffer.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_input() {
        let mut input = vec![10; 10];
        PkcsPadding::pad_input(&mut input);

        let mut expected = vec![10; 10];
        expected.extend(vec![6; 6]);
        assert_eq!(input, expected);
    }

    #[test]
    fn test_strip_input() {
        let mut input = vec![10; 10];
        PkcsPadding::pad_input(&mut input);

        PkcsPadding::strip_output(&mut input);
        assert_eq!(input, vec![10; 10]);
    }

    #[test]
    #[should_panic(expected = "Invalid output size: length is not a multiple of 16.")]
    fn test_strip_output_panic_on_invalid_output_size() {
        PkcsPadding::strip_output(&mut vec![1;15]);
    }

    #[test]
    #[should_panic(expected = "Invalid padding: incorrect padding size.")]
    fn test_strip_output_panic_on_invalid_size() {
        PkcsPadding::strip_output(&mut vec![17; 16]);
    }

    #[test]
    #[should_panic(expected = "Invalid padding: incorrect padding bytes.")]
    fn test_strip_output_panic_on_invalid_padding_bytes() {
        let mut output = vec![6; 6];
        output.extend(vec![16; 10]);

        PkcsPadding::strip_output(&mut output);
    }

    #[test]
    #[should_panic(expected = "Invalid padding: empty output buffer.")]
    fn test_strip_output_panic_on_empty_output() {
        PkcsPadding::strip_output(&mut vec![]);
    }
}
