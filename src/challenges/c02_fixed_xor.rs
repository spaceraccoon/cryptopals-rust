#[cfg(test)]
use crate::utils::encrypt::fixed_xor;

#[test]
fn test_1() {
    let s1 = "1c0111001f010100061a024b53535009181c";
    let s2 = "686974207468652062756c6c277320657965";
    let expected_result = "746865206b696420646f6e277420706c6179";

    assert_eq!(expected_result, fixed_xor(s1, s2));
}
