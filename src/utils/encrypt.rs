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
