#[cfg(test)]
use crate::utils::decrypt::single_byte_xor;

#[test]
fn test_1() {
    let s = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let expected_result = "Cooking MC's like a pound of bacon";

    assert_eq!(expected_result, single_byte_xor(s));
}
