#[cfg(test)]
use crate::utils::{
    decrypt::decrypt_mt19937_stream, encrypt::encrypt_mt19937_stream, rng::MersenneTwister,
    rng::STATE_SIZE,
};
#[cfg(test)]
use byteorder::{ByteOrder, LittleEndian};
#[cfg(test)]
use rand::{thread_rng, Rng};

#[cfg(test)]
// Brute forces all possible seeds to find matching seed with first output.
fn crack_seed_at_index(output: u32, index: usize) -> u32 {
    for i in 0..u32::MAX {
        let mut mt = MersenneTwister {
            state: vec![0; STATE_SIZE],
            index: 0,
        };
        mt.init(i);
        if output == mt.nth(index).unwrap() {
            return i;
        }
    }
    panic!("No seed found!");
}

#[cfg(test)]
pub fn get_seed(ciphertext: &Vec<u8>, known_plaintext: &Vec<u8>, block_size: usize) -> u32 {
    let block_index = ciphertext.len() / block_size - 1;
    let xored_bytes: Vec<u8> = ciphertext[block_index * block_size..(block_index + 1) * block_size]
        .iter()
        .zip(known_plaintext.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    let random_number = <LittleEndian as ByteOrder>::read_u32(&xored_bytes);
    let seed = crack_seed_at_index(random_number, block_index - 1);
    return seed;
}

#[test]
fn test_1() {
    let mut rng = rand::thread_rng();
    let seed: u16 = rng.gen();
    let plaintext: Vec<u8> = [
        (0..rng.gen::<u8>()).map(|_| rng.gen::<u8>()).collect(),
        String::from("AAAAAAAAAAAAAA").into_bytes(),
    ]
    .concat();

    let ciphertext = encrypt_mt19937_stream(&plaintext, seed);
    let cracked_seed = get_seed(&ciphertext, &String::from("AAAA").into_bytes(), 4);
    assert_eq!(u32::from(seed), cracked_seed);
}
