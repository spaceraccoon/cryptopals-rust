#[cfg(test)]
use crate::utils::convert::{bytes_to_base64, hex_to_bytes};

#[test]
fn test_1() {
    let s = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let expected_result =
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    let bytes = hex_to_bytes(s);
    assert_eq!(expected_result, bytes_to_base64(bytes));
}

#[test]
fn test_2() {
    let s = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d12");
    let expected_result =
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29tEg==");
    let bytes = hex_to_bytes(s);
    assert_eq!(expected_result, bytes_to_base64(bytes));
}

#[test]
fn test_3() {
    let s = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d12aa");
    let expected_result =
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29tEqo=");
    let bytes = hex_to_bytes(s);
    assert_eq!(expected_result, bytes_to_base64(bytes));
}
