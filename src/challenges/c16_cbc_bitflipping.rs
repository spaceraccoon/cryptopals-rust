#[cfg(test)]
use crate::utils::{
    decrypt::decrypt_aes_cbc, decrypt::AES_BLOCK_SIZE, encrypt::encrypt_aes_cbc, encrypt::pkcs7_pad,
};
#[cfg(test)]
use openssl::symm::{decrypt, encrypt, Cipher};
#[cfg(test)]
use rand::{thread_rng, Rng};

#[cfg(test)]
// Encrypts plaintext.
pub fn encrypting_oracle(plaintext: String, key: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let mut rng = thread_rng();
    let prefix = Vec::from("comment1=cooking%20MCs;userdata=");
    let suffix = Vec::from(";comment2=%20like%20a%20pound%20of%20bacon");
    let prefix2 = Vec::from("comment1=cooking%20MCs;userdata=");
    let suffix2 = Vec::from(";comment2=%20like%20a%20pound%20of%20bacon");
    let iv = (0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();

    // Quotes out ";" and "=" characters.
    return (
        encrypt_aes_cbc(
            &vec![
                prefix,
                Vec::from(plaintext.replace(&[';', '='][..], "")),
                suffix,
            ]
            .concat(),
            key,
            &iv,
        ),
        iv,
    );
}

#[cfg(test)]
// Decrypts the string and look for the characters ";admin=true;".
pub fn decrypting_oracle(ciphertext: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> bool {
    // Converts unsafely as some characters won't be valid UTF-8 after bitflip -> decrypt.
    let plaintext = unsafe { String::from_utf8_unchecked(decrypt_aes_cbc(&ciphertext, iv, key)) };
    let contains = plaintext.contains(";admin=true;");
    return contains;
}

#[test]
fn test_1() {
    let mut rng = thread_rng();
    // Generates random key.
    let key: Vec<u8> = (0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();
    let plaintext = String::from("$admin$true");
    let (mut ciphertext, iv) = encrypting_oracle(plaintext, &key);
    ciphertext[16] = ciphertext[16] ^ ';' as u8 ^ '$' as u8;
    ciphertext[22] = ciphertext[22] ^ '=' as u8 ^ '$' as u8;
    let result = decrypting_oracle(&ciphertext, &key, &iv);
    assert_eq!(true, result);
}
