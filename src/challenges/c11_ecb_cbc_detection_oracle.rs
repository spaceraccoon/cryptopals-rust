#[cfg(test)]
use crate::utils::{
    decrypt::detect_aes_ecb, decrypt::AES_BLOCK_SIZE, encrypt::encrypt_aes_cbc,
    encrypt::encrypt_aes_ecb,
};
#[cfg(test)]
extern crate rand;
#[cfg(test)]
use rand::{thread_rng, Rng};

#[test]
fn test_1() {
    let mut rng = thread_rng();
    // Generates random key.
    let key: Vec<u8> = (0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();
    // Generates random plaintext.
    let prepend: Vec<u8> = (0..rng.gen_range(5, 10)).map(|_| rng.gen::<u8>()).collect();
    let random_bytes: Vec<u8> = (0..rng.gen::<u8>()).map(|_| rng.gen::<u8>()).collect();
    let append: Vec<u8> = (0..rng.gen_range(5, 10)).map(|_| rng.gen::<u8>()).collect();
    let plaintext = [prepend, random_bytes, append].concat();
    // Create canary by appending same bytes to plaintext, which would encrypt to same blocks in ECB.
    let canary = [plaintext, vec![41; AES_BLOCK_SIZE * 3]].concat();
    let is_aes_ecb: bool = rng.gen::<bool>();
    let mut ciphertext = Vec::new();
    if is_aes_ecb {
        ciphertext = encrypt_aes_ecb(&canary, &key);
    } else {
        let iv: Vec<u8> = (0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();
        ciphertext = encrypt_aes_cbc(&canary, &key, &iv);
    }
    let result = detect_aes_ecb(&ciphertext);
    assert_eq!(is_aes_ecb, result);
}
