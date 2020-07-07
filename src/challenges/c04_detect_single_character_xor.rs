#[cfg(test)]
use crate::utils::{convert::hex_to_bytes, decrypt::single_byte_xor};
#[cfg(test)]
use std::{fs::File, io::BufRead, io::BufReader};

#[test]
fn test_1() {
    let file = File::open("resources/4.txt").unwrap();
    let mut top_score = 0.000;
    let mut decrypted_bytes: Vec<u8> = Vec::new();
    for line in BufReader::new(file).lines() {
        let line_string = line.unwrap();
        let bytes = hex_to_bytes(&String::from(line_string));
        let result = single_byte_xor(&bytes);
        if result.score > top_score {
            top_score = result.score;
            decrypted_bytes = result.decrypted_bytes;
        }
    }

    let expected_result = String::from("Now that the party is jumping\n");
    assert_eq!(expected_result, String::from_utf8(decrypted_bytes).unwrap());
}
