pub trait Encryptor {
    fn encrypt(&mut self) -> Vec<u8>;
}

pub trait PaddingScheme {
    fn pad_input(input_buffer: &mut Vec<u8>);
    fn strip_output(output_buffer: &mut Vec<u8>);
}

pub struct PkscPadding {}
