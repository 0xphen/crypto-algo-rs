mod constants;
mod hash_computation;
mod preprocess;
mod utilities;

/// `hash` computes a cryptographic hash of a given message.
///
/// This function serves as the main interface to the hashing process. It
/// preprocesses the input message, creates a message schedule, compresses
/// the schedule, and then computes the digest bytes. The final hash
/// is represented as a hexadecimal string.
///
/// # Arguments
/// * `message` - A reference to the input message string. This is the data
///   that will be subjected to hashing.
///
/// # Steps:
/// 1. Preprocess the input message to meet certain criteria required for hashing.
/// 2. Generate a message schedule based on the preprocessed message.
/// 3. Compress the message schedule to produce a fixed-size output.
/// 4. Translate the compressed output into its byte representation.
/// 5. Convert each byte into its hexadecimal string equivalent.
///
/// # Returns
/// A `String` containing the hexadecimal representation of the hash digest.
pub fn hash(message: &str) -> String {
    // Preprocess the message
    let preprocessed_msg = preprocess::preprocess_message(message);

    // Create a message schedule
    let msg_schedule = hash_computation::message_schedule::MessageSchedule::new(preprocessed_msg);

    // Compress the message schedule
    let compressed_msg = hash_computation::compression::compress(msg_schedule);

    // Compute the digest bytes
    let digest_bytes = hash_computation::compression::compute_bytes_digest(compressed_msg);

    digest_bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hash_msg() {
        let message = "hello world";
        let digest = hash(message);

        println!("digest: {:?}", digest);
    }
}
