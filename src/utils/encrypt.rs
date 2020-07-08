#[cfg(test)]
use openssl::symm::{encrypt, Cipher};

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
// Sequentially XOR each byte of the key with plaintext.
pub fn encrypt_aes_cbc(plaintext: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    return encrypt(Cipher::aes_128_cbc(), key, Some(iv), plaintext).unwrap();
}

#[cfg(test)]
// Add PKCS7 padding.
pub fn pkcs7_pad(plaintext: &Vec<u8>, block_size: usize) -> Vec<u8> {
    let plaintext_length = plaintext.len();
    let mut padded: Vec<u8> = Vec::new();
    let mut padding_length = block_size;
    if plaintext_length % block_size != 0 {
        padding_length = block_size % (plaintext_length % block_size);
    }
    let mut padding = vec![padding_length as u8; padding_length];
    padded.append(&mut plaintext.clone());
    padded.append(&mut padding);
    return padded;
}
