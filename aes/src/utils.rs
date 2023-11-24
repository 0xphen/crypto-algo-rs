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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
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
}
