pub struct State {
    data: [[u8; 4]; 4],
}

impl State {
    /// Initialize a new state
    pub fn new(bytes: &[u8; 16]) -> Self {
        let mut data = [[0; 4]; 4];

        for (i, chunk) in bytes.chunks(4).enumerate() {
            for (j, &byte) in chunk.iter().enumerate() {
                data[j][i] = byte;
            }
        }

        Self { data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_new_state() {}
}
