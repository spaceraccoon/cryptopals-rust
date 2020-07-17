#[cfg(test)]
use crate::utils::{decrypt::decrypt_aes_cbc, decrypt::AES_BLOCK_SIZE, encrypt::encrypt_aes_cbc};
#[cfg(test)]
use rand::{thread_rng, Rng};

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
    let plaintext: Vec<u8> = vec![255, (AES_BLOCK_SIZE * 3) as u8];
    let ciphertext: Vec<u8> = encrypt_aes_cbc(&plaintext, &key, &key);
    let first_block: Vec<u8> = ciphertext[0..AES_BLOCK_SIZE].to_vec();
    let modified_ciphertext = [
        first_block.clone(),
        vec![0; AES_BLOCK_SIZE],
        first_block.clone(),
    ]
    .concat();
    // Get high ASCII/non-UTF error and failed plaintext.
    let decrypt_result = decrypting_oracle(&modified_ciphertext, &key, &key);
    assert!(decrypt_result.is_err());
    let decrypted_plaintext = decrypt_result.unwrap_err().into_bytes();
    // Recovers key with P'_1 XOR P'_3.
    let recovered_key: Vec<u8> = decrypted_plaintext[0..AES_BLOCK_SIZE]
        .iter()
        .zip(&decrypted_plaintext[AES_BLOCK_SIZE * 2..AES_BLOCK_SIZE * 3])
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    assert_eq!(key, recovered_key);
}
