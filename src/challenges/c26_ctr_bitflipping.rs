#[cfg(test)]
use crate::utils::{decrypt::decrypt_aes_ctr, decrypt::AES_BLOCK_SIZE, encrypt::encrypt_aes_ctr};
#[cfg(test)]
use rand::{thread_rng, Rng};

#[cfg(test)]
// Encrypts plaintext.
pub fn encrypting_oracle(plaintext: String, key: &Vec<u8>) -> Vec<u8> {
    let prefix = Vec::from("comment1=cooking%20MCs;userdata=");
    let suffix = Vec::from(";comment2=%20like%20a%20pound%20of%20bacon");

    // Sanitizes the ";" and "=" characters.
    return encrypt_aes_ctr(
        &vec![
            prefix,
            Vec::from(plaintext.replace(&[';', '='][..], "$")),
            suffix,
        ]
        .concat(),
        key,
        0,
        AES_BLOCK_SIZE,
    );
}

#[cfg(test)]
// Decrypts the string and look for the characters ";admin=true;".
pub fn decrypting_oracle(ciphertext: &Vec<u8>, key: &Vec<u8>) -> bool {
    // Converts unsafely as some characters won't be valid UTF-8 after bitflip -> decrypt.
    let plaintext =
        unsafe { String::from_utf8_unchecked(decrypt_aes_ctr(ciphertext, key, 0, AES_BLOCK_SIZE)) };
    println!("{}", plaintext);
    let contains = plaintext.contains(";admin=true;");
    return contains;
}

#[test]
fn test_1() {
    let mut rng = thread_rng();
    // Generates random key.
    let key: Vec<u8> = (0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();
    let plaintext = String::from("$admin$true");
    let mut ciphertext = encrypting_oracle(plaintext, &key);
    ciphertext[32] = ciphertext[32] ^ ';' as u8 ^ '$' as u8;
    ciphertext[38] = ciphertext[38] ^ '=' as u8 ^ '$' as u8;
    let result = decrypting_oracle(&ciphertext, &key);
    assert_eq!(true, result);
}
