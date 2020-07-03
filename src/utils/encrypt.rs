#[cfg(test)]
use crate::utils::convert::{bytes_to_hex, hex_to_bytes};

#[cfg(test)]
// Takes two equal-length buffers and produces their XOR combination.
pub fn fixed_xor(s1: &str, s2: &str) -> String {
    let byte_array_1 = hex_to_bytes(s1);
    let mut byte_array_1 = match byte_array_1 {
        Ok(byte_array_1) => byte_array_1,
        Err(error) => panic!("Failed to decode hex string: {:?}", error),
    };
    let byte_array_2 = hex_to_bytes(s2);
    let byte_array_2 = match byte_array_2 {
        Ok(byte_array_2) => byte_array_2,
        Err(error) => panic!("Failed to decode hex string: {:?}", error),
    };
    let length = byte_array_1.len();

    for x in 0..length {
        byte_array_1[x] = byte_array_1[x] ^ byte_array_2[x];
    }
    return bytes_to_hex(byte_array_1);
}
