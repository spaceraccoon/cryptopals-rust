#[cfg(test)]
use crate::utils::{convert::hex_to_bytes, decrypt::single_byte_xor};

#[test]
fn test_1() {
    let s = String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let expected_result = String::from("Cooking MC's like a pound of bacon");

    let bytes = hex_to_bytes(&s);
    assert_eq!(
        expected_result,
        String::from_utf8(single_byte_xor(&bytes).decrypted_bytes).unwrap()
    );
}
