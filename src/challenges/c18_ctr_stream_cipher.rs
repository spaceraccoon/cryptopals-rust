#[cfg(test)]
use crate::utils::{convert::base64_to_bytes, decrypt::decrypt_aes_ctr, encrypt::encrypt_aes_ctr};

#[test]
fn test_1() {
    let expected_result = String::from("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ");
    let ciphertext = base64_to_bytes(String::from(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
    ));
    let key = String::from("YELLOW SUBMARINE").into_bytes();
    let plaintext = String::from_utf8(decrypt_aes_ctr(&ciphertext, &key, 0, 16)).unwrap();
    assert_eq!(expected_result, plaintext);
}

#[test]
fn test_2() {
    let expected_result = String::from("The quick brown fox jumped over the lazy dog.");
    let key = String::from("YELLOW SUBMARINE").into_bytes();
    let nonce: u64 = 128;
    let block_size = 16;
    let ciphertext = encrypt_aes_ctr(
        &String::from("The quick brown fox jumped over the lazy dog.").into_bytes(),
        &key,
        nonce,
        block_size,
    );
    let decrypted_plaintext =
        String::from_utf8(decrypt_aes_ctr(&ciphertext, &key, nonce, block_size)).unwrap();
    assert_eq!(expected_result, decrypted_plaintext);
}
