#[cfg(test)]
use crate::utils::{convert::bytes_to_hex, convert::hex_to_bytes, encrypt::fixed_xor};

#[test]
fn test_1() {
    let s1 = String::from("1c0111001f010100061a024b53535009181c");
    let s2 = String::from("686974207468652062756c6c277320657965");
    let expected_result = String::from("746865206b696420646f6e277420706c6179");
    assert_eq!(
        expected_result,
        bytes_to_hex(fixed_xor(hex_to_bytes(&s1), hex_to_bytes(&s2)))
    );
}
