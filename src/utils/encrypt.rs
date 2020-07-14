#[cfg(test)]
use crate::utils::convert::base64_to_bytes;
#[cfg(test)]
use openssl::symm::{encrypt, Cipher};
#[cfg(test)]
use rand::{thread_rng, Rng};

#[cfg(test)]
pub const AES_BLOCK_SIZE: usize = 16;

#[cfg(test)]
// Takes two equal-length buffers and produces their XOR combination.
pub fn fixed_xor(mut bytes_1: Vec<u8>, bytes_2: Vec<u8>) -> Vec<u8> {
    let length = bytes_1.len();

    for x in 0..length {
        bytes_1[x] = bytes_1[x] ^ bytes_2[x];
    }
    return bytes_1;
}

#[cfg(test)]
// Sequentially XOR each byte of the key with plaintext.
pub fn repeating_key_xor(mut plaintext: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let plaintext_length = plaintext.len();
    let key_length = key.len();

    for x in 0..plaintext_length {
        plaintext[x] = plaintext[x] ^ key[x % key_length];
    }
    return plaintext;
}

#[cfg(test)]
// Sequentially XOR each byte of the key with plaintext.
pub fn encrypt_aes_ecb(plaintext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    return encrypt(Cipher::aes_128_ecb(), key, None, plaintext).unwrap();
}

#[cfg(test)]
// Encrypts using AES CBC.
pub fn encrypt_aes_cbc(plaintext: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    return encrypt(Cipher::aes_128_cbc(), key, Some(iv), plaintext).unwrap();
}

#[cfg(test)]
// Randomly encrypts plaintext with ECB or CBC and returns encryption type and ciphertext.
pub fn encryption_oracle_1(plaintext: &Vec<u8>) -> (bool, Vec<u8>) {
    let mut rng = thread_rng();
    // Generates random key.
    let key: Vec<u8> = (0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();
    // Prepend random bytes to plaintext.
    let prepend: Vec<u8> = (0..rng.gen_range(5, 10)).map(|_| rng.gen::<u8>()).collect();
    let append: Vec<u8> = (0..rng.gen_range(5, 10)).map(|_| rng.gen::<u8>()).collect();
    let new_plaintext = [prepend, plaintext.to_vec(), append].concat();
    // Generate ciphertext based on random encryption type
    let is_aes_ecb: bool = rng.gen::<bool>();
    let ciphertext = if is_aes_ecb {
        encrypt_aes_ecb(&new_plaintext, &key)
    } else {
        encrypt_aes_cbc(
            &new_plaintext,
            &key,
            &(0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect(),
        )
    };

    return (is_aes_ecb, ciphertext);
}

#[cfg(test)]
// Encrypts plaintext || unknown-string using AES ECB.
pub fn encryption_oracle_2(plaintext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    // Prepend random bytes to plaintext.
    let append: Vec<u8> = base64_to_bytes(String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));
    let new_plaintext = [plaintext.to_vec(), append].concat();
    let ciphertext = encrypt_aes_ecb(&new_plaintext, key);
    return ciphertext;
}

#[cfg(test)]
// Encrypts prefix || plaintext || unknown-string using AES ECB.
pub fn encryption_oracle_3(prefix: &Vec<u8>, plaintext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    // Prepend random bytes to plaintext.
    let append: Vec<u8> = base64_to_bytes(String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));
    let new_plaintext = [prefix.to_vec(), plaintext.to_vec(), append].concat();
    let ciphertext = encrypt_aes_ecb(&new_plaintext, key);
    return ciphertext;
}

#[cfg(test)]
// Add PKCS7 padding.
pub fn pkcs7_pad(plaintext: &Vec<u8>, block_size: usize) -> Vec<u8> {
    let plaintext_length = plaintext.len();
    let mut padded: Vec<u8> = Vec::new();
    let mut padding_length = block_size;
    if plaintext_length % block_size != 0 {
        padding_length = block_size - (plaintext_length % block_size);
    }
    let mut padding = vec![padding_length as u8; padding_length];
    padded.append(&mut plaintext.clone());
    padded.append(&mut padding);
    return padded;
}

#[cfg(test)]
// Ecnrypts CTR.
pub fn encrypt_aes_ctr(
    plaintext: &Vec<u8>,
    key: &Vec<u8>,
    nonce: u64,
    block_size: usize,
) -> Vec<u8> {
    let mut counter: u64 = 0;
    let mut ciphertext = vec![0; plaintext.len()];

    for (block_index, block) in plaintext.chunks(block_size).enumerate() {
        let block_offset = block_index * block_size;
        let input: Vec<u8> = [nonce.to_le_bytes(), counter.to_le_bytes()].concat();
        let keystream = encrypt(Cipher::aes_128_ecb(), key, None, &input).unwrap();
        for (byte_index, byte) in block.iter().enumerate() {
            ciphertext[block_offset + byte_index] = byte ^ keystream[byte_index];
        }
        counter = counter + 1;
    }

    return ciphertext;
}
