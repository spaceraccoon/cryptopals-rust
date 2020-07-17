#[cfg(test)]
use crate::utils::{decrypt::decrypt_aes_cbc, decrypt::AES_BLOCK_SIZE, encrypt::generate_sha1_mac};
#[cfg(test)]
use rand::{thread_rng, Rng};
#[cfg(test)]
use sha1::{Digest, Sha1};

#[cfg(test)]
// Decrypts the string, throwing an error if unable to convert to UTF8.
pub fn decrypting_oracle(
    ciphertext: &Vec<u8>,
    key: &Vec<u8>,
    iv: &Vec<u8>,
) -> Result<Vec<u8>, std::string::FromUtf8Error> {
    // Attempts to convert bytes to UTF8 string.
    match String::from_utf8(decrypt_aes_cbc(&ciphertext, iv, key)) {
        Ok(plaintext) => return Ok(plaintext.into_bytes()),
        Err(e) => return Err(e),
    };
}

#[test]
fn test_1() {
    let mut rng = thread_rng();
    // Generates random key.
    let key: Vec<u8> = (0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();
    let hash: Vec<u8> = generate_sha1_mac(
        &key,
        &Vec::from("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"),
    );
    let expected_result = generate_sha1_mac(
        &key,
        &Vec::from("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"),
    );
    assert_eq!(expected_result, hash);
}
