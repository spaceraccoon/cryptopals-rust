#[cfg(test)]
use crate::utils::encrypt::pkcs7_pad;

#[test]
fn test_1() {
    let bytes = String::from("YELLOW SUBMARINE").into_bytes();
    let size = 20;
    let expected_result = vec![
        89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4,
    ];

    assert_eq!(expected_result, pkcs7_pad(&bytes, size));
}

#[test]
fn test_2() {
    let bytes = vec![1, 1, 1, 1, 1, 1, 1, 1];
    let size = 8;
    let expected_result = vec![1, 1, 1, 1, 1, 1, 1, 1, 8, 8, 8, 8, 8, 8, 8, 8];

    assert_eq!(expected_result, pkcs7_pad(&bytes, size));
}
