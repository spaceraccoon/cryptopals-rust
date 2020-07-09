#[cfg(test)]
use crate::utils::{
    decrypt::detect_aes_ecb, decrypt::AES_BLOCK_SIZE, encrypt::encryption_oracle_1,
};
#[cfg(test)]
extern crate rand;
#[cfg(test)]
use rand::{thread_rng, Rng};

#[test]
fn test_1() {
    let mut rng = thread_rng();
    // Generates random plaintext.
    let random_bytes: Vec<u8> = (0..rng.gen::<u8>()).map(|_| rng.gen::<u8>()).collect();
    // Create canary by appending same bytes to plaintext, which would encrypt to same blocks in ECB.
    let canary = [random_bytes, vec![41; AES_BLOCK_SIZE * 3]].concat();
    let (is_aes_ecb, ciphertext) = encryption_oracle_1(&canary);
    let result = detect_aes_ecb(&ciphertext);
    assert_eq!(is_aes_ecb, result);
}
