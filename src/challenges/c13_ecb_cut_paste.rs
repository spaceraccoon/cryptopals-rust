#[cfg(test)]
use crate::utils::{
    convert::profile_for, decrypt::decrypt_aes_ecb, decrypt::AES_BLOCK_SIZE,
    encrypt::encrypt_aes_ecb,
};
#[cfg(test)]
use rand::{thread_rng, Rng};
#[cfg(test)]
use regex::Regex;

#[test]
fn test_1() {
    let mut rng = thread_rng();
    let fixed_key: Vec<u8> = (0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();
    let prefix = encrypt_aes_ecb(
        &Vec::from(profile_for(&String::from("dead@beef.com"))),
        &fixed_key,
    )[0..(AES_BLOCK_SIZE * 2)]
        .to_vec();
    let admin_bytes = encrypt_aes_ecb(
        &Vec::from(profile_for(&String::from("foo@bar.coadmin"))),
        &fixed_key,
    )[AES_BLOCK_SIZE..]
        .to_vec();
    let decrypted_profile = decrypt_aes_ecb(&[prefix, admin_bytes].concat(), &fixed_key);
    // Extracts role from parsed decrypted profile.
    let re = Regex::new(r"role=(\w+)").unwrap();
    let role = re
        .captures(&std::str::from_utf8(&decrypted_profile).unwrap())
        .unwrap()
        .get(1)
        .map_or("", |m| m.as_str());
    let expected_result = "admin";
    assert_eq!(expected_result, role);
}
