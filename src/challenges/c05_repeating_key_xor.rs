#[cfg(test)]
use crate::utils::{convert::bytes_to_hex, encrypt::repeating_key_xor};

#[test]
fn test_1() {
    let plaintext =
        String::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
    let key = String::from("ICE");
    let expected_result =
        String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    assert_eq!(
        expected_result,
        bytes_to_hex(repeating_key_xor(plaintext.into_bytes(), key.into_bytes()))
    );
}
