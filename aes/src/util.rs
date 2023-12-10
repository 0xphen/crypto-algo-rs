/// Generates a 4x4 matrix from an array of 16 bytes
pub fn gen_matrix(bytes: &[u8; 16]) -> [[u8; 4]; 4] {
    let mut matrix = [[0; 4]; 4];

    for (i, chunk) in bytes.chunks(4).enumerate() {
        for (j, &byte) in chunk.iter().enumerate() {
            matrix[i][j] = byte;
        }
    }

    matrix
}

/// Converts a vector of bytes into a vector of 4-byte arrays.
///
/// This function chunks the input bytes into arrays of four bytes each.
/// It panics if the input vector's length is not a multiple of 4.
///
/// # Arguments
/// * `bytes` - A reference to a vector of bytes (`Vec<u8>`).
///
/// # Returns
/// A `Vec<[u8; 4]>` where each element is a 4-byte array from the input.
pub fn chunk_bytes_into_quads(bytes: &Vec<u8>) -> Vec<[u8; 4]> {
    if bytes.len() % 4 != 0 {
        panic!("Input not a multiple of 4");
    }

    let mut buffer: Vec<[u8; 4]> = vec![[0u8; 4]; bytes.len() / 4];

    for (i, chunk) in bytes.chunks(4).enumerate() {
        for (j, &byte) in chunk.iter().enumerate() {
            buffer[i][j] = byte;
        }
    }

    buffer
}

/// Performs element-wise XOR between each row of a matrix `a` (Vec<[u8; 4]>) and a fixed-size array `b` ([[u8; 4]; 4]).
pub fn xor_matrix_with_array(a: &Vec<[u8; 4]>, b: [[u8; 4]; 4]) -> Vec<[u8; 4]> {
    let mut buffer: Vec<[u8; 4]> = vec![[0u8; 4]; a.len()];
    for (i, (row_a, row_b)) in a.iter().zip(b.iter()).enumerate() {
        for (j, (val_a, val_b)) in row_a.iter().zip(row_b.iter()).enumerate() {
            buffer[i][j] = val_a ^ val_b;
        }
    }

    buffer
}

/// Performs element-wise XOR operation on two 4x4 state matrices.
/// Returns a new 4x4 matrix resulting from the XOR of `a` and `b`.
pub fn xor_matrices(a: [[u8; 4]; 4], b: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    let mut new_state = [[0; 4]; 4];
    for (i, (row_a, row_b)) in a.iter().zip(b.iter()).enumerate() {
        for (j, (&val_a, &val_b)) in row_a.iter().zip(row_b.iter()).enumerate() {
            new_state[i][j] = val_a ^ val_b;
        }
    }

    new_state
}

pub fn xor_array(a: [u8; 4], b: [u8; 4]) -> [u8; 4] {
    let mut result = [0u8; 4];
    for i in 0..4 {
        result[i] = a[i] ^ b[i];
    }

    result
}

#[inline]
pub fn rotate_left(matrix: &[u8; 4], n: usize) -> [u8; 4] {
    let n = n % matrix.len(); // Skip redundant rotations.
    let mut new_matrix: [u8; 4] = [0; 4];

    let (left, right) = matrix.split_at(n);
    new_matrix[..right.len()].copy_from_slice(right);
    new_matrix[right.len()..].copy_from_slice(left);

    new_matrix
}

/// Multiplies two elements in GF(2^8).
pub fn galois_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0; // Initialize the accumulator to 0. This will store the result.
    let m: u8 = 0x1B; // The irreducible polynomial x^8 + x^4 + x^3 + x + 1, used for modular reduction.

    // Iterate over each bit of `b`.
    for i in 0..8 {
        // Check if the i-th bit of `b` is set.
        if b & 0x1 != 0 {
            // If the i-th bit of `b` is set, XOR `a` with `p`.
            // This step adds the contribution of `a` to the accumulator.
            p ^= a;
        }

        // Check if the most significant bit (MSB) of `a` is set.
        let msb_set = a & 0x80 != 0;

        // Shift `a` left by 1 (multiply by x).
        // This operation aligns `a` with the next term of `b`.
        a <<= 1;
        b >>= 1;

        // Perform modular reduction if the MSB was set before the shift.
        if msb_set {
            // XOR `a` with the irreducible polynomial `m` for modular reduction.
            a ^= m;
        }
    }

    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_matrices() {
        let a: [[u8; 4]; 4] = [
            [184, 3, 184, 3],
            [186, 159, 186, 159],
            [199, 73, 199, 73],
            [73, 223, 73, 223],
        ];

        let b: [[u8; 4]; 4] = [
            [144, 105, 242, 11],
            [151, 108, 244, 15],
            [52, 207, 87, 172],
            [80, 250, 51, 153],
        ];

        let result = xor_matrices(a, b);

        assert_eq!(
            result,
            [
                [40, 106, 74, 8],
                [45, 243, 78, 144,],
                [243, 134, 144, 229],
                [25, 37, 122, 70]
            ]
        );
    }

    #[test]
    fn test_rotate_left() {
        let result = rotate_left(&[1, 2, 3, 4], 3);
        assert_eq!(result, [4, 1, 2, 3]);
    }

    #[test]
    fn test_galois_mul() {
        let result = galois_mul(15, 6);
        assert_eq!(result, 34);
    }
}
