#[cfg(test)]
use crate::utils::{
    analyze::{bytes_to_score, compute_edit_distance},
    convert::hex_to_bytes,
    encrypt::repeating_key_xor,
};
#[cfg(test)]
use openssl::symm::{decrypt, encrypt, Cipher};

#[cfg(test)]
pub struct DecryptResult {
    pub decrypted_bytes: Vec<u8>,
    pub key: u8,
    pub score: f32,
}

#[cfg(test)]
pub const AES_BLOCK_SIZE: usize = 16;

#[cfg(test)]
// Guesses the most likely keysize for a repeating-key XOR plaintext.
pub fn guess_keysize(bytes: &Vec<u8>) -> u8 {
    let mut keysize: u8 = 0;
    let length = bytes.len();
    let mut edit_distance = f64::MAX;
    for x in 2..40 {
        // Drops keysizes that are less than bytelength / 2.
        if length / x < 2 {
            break;
        }
        let mut total_distance = 0;
        let chunks = bytes.chunks_exact(2 * x);
        for chunk in chunks {
            total_distance = total_distance
                + (compute_edit_distance(chunk[0..x].to_vec(), chunk[x..2 * x].to_vec())
                    / x as u64);
        }
        let candidate_edit_distance =
            total_distance as f64 / (bytes.chunks_exact(2 * x).len() as f64);
        if candidate_edit_distance < edit_distance {
            edit_distance = candidate_edit_distance;
            keysize = x as u8;
        }
    }
    return keysize;
}

#[cfg(test)]
// Guesses the most likely key for a repeating-key XOR plaintext and size.
pub fn guess_repeating_key(bytes: &Vec<u8>, size: usize) -> Vec<u8> {
    let mut key: Vec<u8> = vec![0; size];

    for x in 0..size {
        let single_bytes = bytes[x..].iter().step_by(size).map(|x| x.clone()).collect();
        let result = single_byte_xor(&single_bytes);
        key[x] = result.key;
    }

    return key;
}

#[cfg(test)]
// Finds single character XOR and decrypts the message.
pub fn single_byte_xor(bytes: &Vec<u8>) -> DecryptResult {
    let length = bytes.len();
    let mut top_score: f32 = 0.000;
    let mut top_key: u8 = 0;
    let mut decrypted_bytes: Vec<u8> = Vec::new();

    // Loops through all possible byte values.
    for x in 0..255 {
        let xor_array: Vec<u8> = vec![x; length];
        // XORs entire byte array with single character.
        let xored_array: Vec<u8> = bytes
            .iter()
            .zip(xor_array.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        // Converts XORed byte array into frequency score.
        let score = bytes_to_score(&xored_array);
        if score > top_score {
            top_score = score;
            top_key = x;
            decrypted_bytes = xored_array;
        }
    }
    let result: DecryptResult = DecryptResult {
        decrypted_bytes: decrypted_bytes,
        key: top_key,
        score: top_score,
    };
    return result;
}

#[cfg(test)]
// Decrypts AES in ECB mode.
pub fn decrypt_aes_ecb(ciphertext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let plaintext = decrypt(cipher, key, None, ciphertext).unwrap();

    return plaintext;
}

#[cfg(test)]
// Detects AES in ECB mode.
pub fn detect_aes_ecb(bytes: &Vec<u8>) -> bool {
    let mut blocks: Vec<&[u8]> = bytes.chunks(AES_BLOCK_SIZE).collect();
    blocks.sort();
    blocks.dedup();
    return blocks.concat().len() != bytes.len();
}

#[cfg(test)]
pub fn xor_vectors(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
    let xored: Vec<u8> = v1.iter().zip(v2.iter()).map(|(&x1, &x2)| x1 ^ x2).collect();
    return xored;
}

#[cfg(test)]
// Decrypts AES in CBC mode.
pub fn decrypt_aes_cbc(ciphertext: &Vec<u8>, iv: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut plaintext = Vec::new();
    let blocks: Vec<&[u8]> = ciphertext.chunks(AES_BLOCK_SIZE).collect();
    let num_blocks = blocks.len();
    for x in 0..num_blocks {
        // For single blocks, OpenSSL requires additional padding before decryping.
        let mut padding = encrypt(
            openssl::symm::Cipher::aes_128_ecb(),
            key,
            None,
            &[AES_BLOCK_SIZE as u8; AES_BLOCK_SIZE],
        )
        .unwrap();
        padding.truncate(AES_BLOCK_SIZE);
        let mut padded_block = blocks[x].to_vec();
        padded_block.extend_from_slice(&padding);
        let decrypted_block = decrypt_aes_ecb(&padded_block, key);
        if x == 0 {
            plaintext.append(&mut xor_vectors(&decrypted_block, iv));
        } else {
            plaintext.append(&mut xor_vectors(&decrypted_block, &blocks[x - 1].to_vec()));
        }
    }

    return plaintext;
}

#[test]
fn guess_keysize_test_1() {
    let ciphertext = String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    let expected_result = 3;
    assert_eq!(expected_result, guess_keysize(&hex_to_bytes(&ciphertext)));
}

#[test]
fn guess_repeating_key_test_1() {
    let ciphertext = String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    let expected_result = String::from("ICE");

    assert_eq!(
        expected_result,
        String::from_utf8(guess_repeating_key(&hex_to_bytes(&ciphertext), 3)).unwrap()
    );
}

#[test]
fn break_repeating_key_test_1() {
    let ciphertext = hex_to_bytes(&String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"));
    let expected_result =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let keysize = usize::from(guess_keysize(&ciphertext));
    let key = guess_repeating_key(&ciphertext, keysize);

    assert_eq!(
        expected_result,
        String::from_utf8(repeating_key_xor(ciphertext, key)).unwrap()
    );
}
