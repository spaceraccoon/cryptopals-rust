#[cfg(test)]
use crate::utils::{decrypt::break_aes_ecb_simple, encrypt::encryption_oracle_2};

#[test]
fn test_1() {
    let plaintext = break_aes_ecb_simple(&encryption_oracle_2);
    let expected_result = String::from("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n");
    assert_eq!(expected_result, String::from_utf8(plaintext).unwrap());
}
