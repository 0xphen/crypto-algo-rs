/// Circularly right-shifts a 32-bit number by `n` positions.
///
/// This function takes a 32-bit number represented as a byte array `input` and circularly
/// shifts it to the right by `n` positions.
/// If `n` exceeds 32, it wraps around, so it essentially does `n % 32`.
/// In SHA-256, the max value of n is 22, but this function is generalized to handle up to 32.
///
/// # Arguments
///
/// * `input` - A 4-byte array representing the 32-bit number to be shifted.
/// * `n` - Number of positions to shift to the right. If exceeds 32, it wraps around.
///
/// # Returns
/// A 4-byte array representing the shifted number.
pub fn rotr(input: [u8; 4], n: usize) -> [u8; 4] {
    // Ensure n is in range [0, 31] for predictable behavior.
    let n = n % 32;

    // Convert the input byte array to a 32-bit unsigned integer.
    let num = u32::from_be_bytes(input);

    // Perform the circular right shift.
    let shifted = (num >> n) | (num << (32 - n));

    // Convert the shifted 32-bit unsigned integer back to a byte array and return.
    shifted.to_be_bytes()
}

/// Performs a right shift on a 32-bit number represented as a byte array.
///
/// # Parameters
/// - `input`: A 4-byte array representing a 32-bit number.
/// - `n`: The number of positions to shift to the right.
///
/// # Returns
/// A 4-byte array representing the shifted 32-bit number.
pub fn shr(input: [u8; 4], n: usize) -> [u8; 4] {
    let n = n % 32;
    let shifted = u32::from_be_bytes(input) >> n;
    shifted.to_be_bytes()
}

/// Performs bitwise addition modulo 2 on two byte arrays of length 4.
///
/// # Arguments
///
/// * `a` - First byte array.
/// * `b` - Second byte array.
///
/// # Returns
///
/// A new byte array of length 4 where each byte is the result of
/// the XOR operation on corresponding bytes of `a` and `b`.
pub fn add_mod_2(a: [u8; 4], b: [u8; 4]) -> [u8; 4] {
    let mut result = [0u8; 4];
    for i in 0..4 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Adds two 32-bit numbers represented as byte arrays, modulo 2^32.
///
/// # Parameters:
/// - `a`: First number represented as a big-endian byte array.
/// - `b`: Second number represented as a big-endian byte array.
///
/// # Returns:
/// - A big-endian byte array representing the sum of `a` and `b`, modulo 2^32.
pub fn add_mod_2_32(a: [u8; 4], b: [u8; 4]) -> [u8; 4] {
    // Convert byte arrays to u32 integers in big-endian format
    let num_a = u32::from_be_bytes(a);
    let num_b = u32::from_be_bytes(b);

    // Perform addition with wrapping to handle overflow
    let sum = num_a.wrapping_add(num_b);

    // Convert the result back to a big-endian byte array
    sum.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circular_rotate_right() {
        let result = rotr([11, 0, 24, 32], 3);
        assert_eq!(result, [1, 96, 3, 4]);
    }

    #[test]
    fn right_shift() {
        let result = shr([12, 8, 16, 4], 3);
        assert_eq!(result, [1, 129, 2, 0]);
    }

    #[test]
    fn mod_2() {
        let result = add_mod_2([12, 10, 32, 6], [0, 4, 8, 2]);
        assert_eq!(result, [12, 14, 40, 4]);
    }

    #[test]
    fn mod_32() {
        let result = add_mod_2_32([12, 10, 32, 6], [0, 4, 8, 2]);
        assert_eq!(result, [12, 14, 40, 8]);
    }

    // #[test]
    // fn mod_32() {
    //     let result = add_mod_2_32([1, 143, 233, 5], [82, 101, 104, 66]);
    //     assert_eq!(result, [83, 245, 81, 71]);
    // }
}
