#[cfg(test)]
use crate::utils::{
    analyze::{bytes_to_score, compute_edit_distance},
    convert::hex_to_bytes,
    encrypt::repeating_key_xor,
};
#[cfg(test)]
use crate::utils::{rng::MersenneTwister, rng::STATE_SIZE};
#[cfg(test)]
use byteorder::{ByteOrder, LittleEndian};
#[cfg(test)]
use openssl::symm::{decrypt, encrypt, Cipher};
#[cfg(test)]
use rand::{thread_rng, Rng};

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
    return decrypt(Cipher::aes_128_ecb(), key, None, ciphertext).unwrap();
}

#[cfg(test)]
// Get AES in ECB mode encryption block size.
pub fn get_aes_ecb_block_size(
    oracle: &dyn Fn(&Vec<u8>, &Vec<u8>) -> Vec<u8>,
    fixed_key: &Vec<u8>,
) -> usize {
    let mut max_length = oracle(&Vec::new(), fixed_key).len();
    let mut first_padding = 0;
    let mut second_padding = 0;
    for x in 1..128 {
        let plaintext: Vec<u8> = vec![1; x];
        let ciphertext_length = oracle(&plaintext, fixed_key).len();
        if ciphertext_length > max_length {
            if first_padding == 0 {
                first_padding = x;
                max_length = ciphertext_length;
            } else {
                second_padding = x;
                break;
            }
        }
    }
    return second_padding - first_padding;
}

#[cfg(test)]
// Get AES in ECB mode encryption block size.
pub fn get_aes_ecb_block_size_2(
    prefix: &Vec<u8>,
    oracle: &dyn Fn(&Vec<u8>, &Vec<u8>, &Vec<u8>) -> Vec<u8>,
    fixed_key: &Vec<u8>,
) -> usize {
    let mut max_length = oracle(prefix, &Vec::new(), fixed_key).len();
    let mut first_padding = 0;
    let mut second_padding = 0;
    for x in 1..128 {
        let plaintext: Vec<u8> = vec![1; x];
        let ciphertext_length = oracle(prefix, &plaintext, fixed_key).len();
        if ciphertext_length > max_length {
            if first_padding == 0 {
                first_padding = x;
                max_length = ciphertext_length;
            } else {
                second_padding = x;
                break;
            }
        }
    }
    return second_padding - first_padding;
}

#[cfg(test)]
// Breaks AES in ECB mode encryption one byte at a time (simple).
pub fn break_aes_ecb_simple(oracle: &dyn Fn(&Vec<u8>, &Vec<u8>) -> Vec<u8>) -> Vec<u8> {
    let mut rng = thread_rng();
    let fixed_key: Vec<u8> = (0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();
    // Discovers the block size of the cipher.
    let block_size = get_aes_ecb_block_size(oracle, &fixed_key);
    // Detects that the function is using ECB.
    let is_aes_ecb = detect_aes_ecb(&oracle(&vec![1; block_size * 2], &fixed_key));
    if !is_aes_ecb {
        panic!("Not AES ECB");
    }
    let ciphertext = oracle(&Vec::new(), &fixed_key);
    let ciphertext_length = ciphertext.len();
    let num_blocks = ciphertext_length / block_size;
    let mut decrypted_bytes = Vec::new();
    // Enumerate through each byte of ciphertext, matching every possible last byte to known reference block.
    // Technically O(n) but feels like it's taking too long?
    for x in 0..num_blocks {
        for y in 1..(block_size + 1) {
            let reference_block = oracle(&vec![1; block_size - y], &fixed_key)
                [(x * block_size)..((x + 1) * block_size)]
                .to_vec();
            for z in 0..255 {
                let comparison_block = oracle(
                    &[vec![1; block_size - y], decrypted_bytes.to_vec(), vec![z]].concat(),
                    &fixed_key,
                )[(x * block_size)..((x + 1) * block_size)]
                    .to_vec();
                if comparison_block == reference_block {
                    decrypted_bytes.append(&mut vec![z]);
                    break;
                }
            }
        }
    }
    // Trims the last byte.
    decrypted_bytes.truncate(decrypted_bytes.len() - 1);
    return decrypted_bytes;
}

#[cfg(test)]
// Breaks AES in ECB mode encryption one byte at a time (hard).
pub fn break_aes_ecb_hard(oracle: &dyn Fn(&Vec<u8>, &Vec<u8>, &Vec<u8>) -> Vec<u8>) -> Vec<u8> {
    let mut rng = thread_rng();
    let fixed_key: Vec<u8> = (0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();
    let prefix: Vec<u8> = (0..rng.gen_range(1, AES_BLOCK_SIZE * 10))
        .map(|_| rng.gen::<u8>())
        .collect();
    let prefix_length = prefix.len();
    // Discovers the block size of the cipher.
    let block_size = get_aes_ecb_block_size_2(&prefix, oracle, &fixed_key);
    // Detects that the function is using ECB.
    let is_aes_ecb = detect_aes_ecb(&oracle(&prefix, &vec![1; block_size * 3], &fixed_key));
    if !is_aes_ecb {
        panic!("Not AES ECB");
    }

    // Calculates offset to balance prefix.
    let mut offset_length = 0;
    for x in 0..block_size {
        let input = [vec![1; x], vec![2; block_size * 2]].concat();
        if detect_aes_ecb(&oracle(&prefix, &input, &fixed_key)) {
            offset_length = x;
            break;
        }
    }

    let ciphertext = oracle(&prefix, &vec![1; offset_length], &fixed_key);
    let ciphertext_length = ciphertext.len();
    let num_blocks = ciphertext_length / block_size;
    let mut decrypted_bytes = Vec::new();

    // Enumerate through each byte of ciphertext, matching every possible last byte to known reference block.
    // Technically O(n) but feels like it's taking too long?
    for x in ((prefix_length + offset_length) / block_size)..num_blocks {
        for y in 1..(block_size + 1) {
            let reference_block = oracle(
                &prefix,
                &[vec![1; offset_length], vec![2; block_size - y]].concat(),
                &fixed_key,
            )[(x * block_size)..((x + 1) * block_size)]
                .to_vec();
            for z in 0..255 {
                let comparison_block = oracle(
                    &prefix,
                    &[
                        vec![1; offset_length],
                        vec![2; block_size - y],
                        decrypted_bytes.to_vec(),
                        vec![z],
                    ]
                    .concat(),
                    &fixed_key,
                )[(x * block_size)..((x + 1) * block_size)]
                    .to_vec();
                if comparison_block == reference_block {
                    decrypted_bytes.append(&mut vec![z]);
                    break;
                }
            }
        }
    }
    // Trims the last byte.
    decrypted_bytes.truncate(decrypted_bytes.len() - 1);
    return decrypted_bytes;
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

#[cfg(test)]
// Add PKCS7 padding.
pub fn pkcs7_unpad(plaintext: &Vec<u8>) -> Vec<u8> {
    let plaintext_length = plaintext.len();
    let padding_length = plaintext[plaintext_length - 1] as usize;
    let unpadded: Vec<u8> = plaintext[0..(plaintext_length - padding_length)].to_vec();
    return unpadded;
}

#[cfg(test)]
// Decrypts CTR.
pub fn decrypt_aes_ctr(
    ciphertext: &Vec<u8>,
    key: &Vec<u8>,
    nonce: u64,
    block_size: usize,
) -> Vec<u8> {
    let mut counter: u64 = 0;
    let mut plaintext = vec![0; ciphertext.len()];

    for (block_index, block) in ciphertext.chunks(block_size).enumerate() {
        let block_offset = block_index * block_size;
        let input: Vec<u8> = [nonce.to_le_bytes(), counter.to_le_bytes()].concat();
        let keystream = encrypt(Cipher::aes_128_ecb(), key, None, &input).unwrap();
        for (byte_index, byte) in block.iter().enumerate() {
            plaintext[block_offset + byte_index] = byte ^ keystream[byte_index];
        }
        counter = counter + 1;
    }

    return plaintext;
}

#[cfg(test)]
// Decrypts using MT19937 PRNG stream.
pub fn decrypt_mt19937_stream(ciphertext: &Vec<u8>, seed: u16) -> Vec<u8> {
    let mut buffer_index: usize = 0;
    let length = ciphertext.len();
    let buffer = &mut [0u8; 4];
    let mut mt = MersenneTwister {
        state: vec![0; STATE_SIZE],
        index: 0,
    };
    mt.init(u32::from(seed));
    let mut plaintext = vec![0; length];

    for (byte_index, byte) in ciphertext.iter().enumerate() {
        // Enters next random number to buffer and resets index.
        if buffer_index == 4 {
            <LittleEndian as ByteOrder>::write_u32(buffer, mt.next().unwrap());
            buffer_index = 0;
        }
        plaintext[byte_index] = byte ^ buffer[buffer_index];
        buffer_index += 1;
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
