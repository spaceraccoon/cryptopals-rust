#[cfg(test)]
use crate::utils::convert::{bytes_to_score, hex_to_bytes};

#[cfg(test)]
// Finds single character XOR and decrypts the message.
pub fn single_byte_xor(s: &str) -> String {
    let byte_array = hex_to_bytes(s);
    let byte_array = match byte_array {
        Ok(byte_array) => byte_array,
        Err(error) => panic!("Failed to decode string: {:?}", error),
    };
    let length = byte_array.len();
    let mut top_score: f32 = 0.000;
    let mut decrypted_byte_array: Vec<u8> = Vec::new();

    // Loops through all possible byte values.
    for x in 0..255 {
        let xor_array: Vec<u8> = vec![x; length];
        // XORs entire byte array with single character.
        let xored_array: Vec<u8> = byte_array
            .iter()
            .zip(xor_array.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        // Converts XORed byte array into frequency score.
        let score = bytes_to_score(&xored_array);
        if score > top_score {
            top_score = score;
            decrypted_byte_array = xored_array;
        }
    }
    return String::from_utf8(decrypted_byte_array).unwrap();
}
