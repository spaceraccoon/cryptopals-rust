#[cfg(test)]
use crate::utils::{
    analyze::validate_pkcs7_padding, convert::base64_to_bytes, decrypt::decrypt_aes_cbc,
    decrypt::pkcs7_unpad, decrypt::AES_BLOCK_SIZE, encrypt::encrypt_aes_cbc,
};
#[cfg(test)]
use rand::{seq::SliceRandom, thread_rng, Rng};

#[cfg(test)]
// Encrypts plaintext.
pub fn encrypting_oracle(plaintext: &Vec<u8>, key: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let mut rng = thread_rng();
    let iv = (0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();

    return (encrypt_aes_cbc(plaintext, key, &iv), iv);
}

#[cfg(test)]
// Decrypts the string and look for the characters ";admin=true;".
pub fn padding_oracle(ciphertext: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>) -> bool {
    validate_pkcs7_padding(&decrypt_aes_cbc(&ciphertext, iv, key))
}

#[test]
fn test_1() {
    let mut rng = thread_rng();
    // Generates random key.
    let key: Vec<u8> = (0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();
    let base64_strings = vec![
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];
    // Selects random base64 string.challenges
    let base64_string = String::from(*base64_strings.choose(&mut rand::thread_rng()).unwrap());
    let expected_result = base64_to_bytes(base64_string);
    let (ciphertext, iv) = encrypting_oracle(&expected_result, &key);
    let length = ciphertext.len();
    let mut plaintext = vec![0; length];

    let blocks: Vec<&[u8]> = ciphertext.chunks(AES_BLOCK_SIZE).collect();
    for (block_index, block) in blocks.iter().enumerate() {
        let block_offset = block_index * AES_BLOCK_SIZE;
        // For first block, uses IV instead of previous block.
        let previous_block;
        if block_index == 0 {
            previous_block = iv.clone();
        } else {
            previous_block = Vec::from(blocks[block_index - 1]);
        };
        // Inits intermediate values.
        let mut intermediate = vec![0; AES_BLOCK_SIZE];
        for i in (0..AES_BLOCK_SIZE).rev() {
            let padding = (AES_BLOCK_SIZE - i) as u8;
            let mut attack = vec![0; AES_BLOCK_SIZE];
            // For any padding greater than 1, ensure that rest of attack block will cause plaintext bytes after targeted byte to equal padding.
            if padding > 1 {
                for y in 1..padding as usize {
                    attack[AES_BLOCK_SIZE - y] = padding ^ intermediate[AES_BLOCK_SIZE - y];
                }
            }
            // Iterates through all possible values for C'n.
            for x in 0..255 {
                attack[i] = x;
                if padding_oracle(&Vec::from(*block), &key, &attack) {
                    println!("Correct is {}", x);
                    intermediate[i] = padding ^ x;
                    plaintext[block_offset + i] = previous_block[i] ^ intermediate[i];
                    break;
                }
            }
        }
    }

    assert_eq!(expected_result, pkcs7_unpad(&plaintext));
}
