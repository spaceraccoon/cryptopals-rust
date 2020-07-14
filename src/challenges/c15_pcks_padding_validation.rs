#[cfg(test)]
use crate::utils::analyze::validate_pkcs7_padding;

#[test]
fn test_1() {
    let plaintext = Vec::from("ICE ICE BABY\x04\x04\x04\x04");
    let expected_result = true;
    assert_eq!(expected_result, validate_pkcs7_padding(&plaintext));
}

#[test]
fn test_2() {
    let plaintext = Vec::from("ICE ICE BABY\x05\x05\x05\x05");
    let expected_result = false;
    assert_eq!(expected_result, validate_pkcs7_padding(&plaintext));
}

#[test]
fn test_3() {
    let plaintext = Vec::from("ICE ICE BABY\x01\x02\x03\x04");
    let expected_result = false;
    assert_eq!(expected_result, validate_pkcs7_padding(&plaintext));
}
