/// Performs a circular right shift on a binary,
/// whose length is greater than `n`.
///
/// # Arguments
/// * `b` - Binary to perform a circular right shift on.
/// * `n` - The number of right shifts to perform.
///
/// # Returns
/// A new binary that has been circular rotated `n` times.
pub fn rotr(b: &str, n: usize) -> String {
    if b.len() <= n {
        panic!("n {:?} is larger than b", n);
    }

    let chars_b = b.chars().collect::<Vec<_>>();
    let elements_to_rotate: String = chars_b.iter().rev().take(n).rev().collect();
    let left_over_elements: String = chars_b.iter().rev().skip(n).rev().collect();

    elements_to_rotate + &left_over_elements
}

pub fn shr(b: &str, n: usize) -> String {
    let chars_b = b.chars().collect::<Vec<_>>();
    let a = chars_b.into_iter().take(n).collect::<String>();
    let pad = "0".repeat(n);

    pad + &a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circular_rotate_right() {
        let result = rotr("0110100001100101011011000110110001101111001000000111011101101111011100100110110001100100100000000000000000", 18);
        assert_eq!(result, "1000000000000000000110100001100101011011000110110001101111001000000111011101101111011100100110110001100100");
    }

    #[test]
    fn right_shift() {
        let result = shr("101100", 3);
        assert_eq!(result, "000101");
    }
}
