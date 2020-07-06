#[cfg(test)]
// Converts character to frequency score.
fn char_to_score(char: char) -> f32 {
    match char {
        'a' => 8.497,
        'b' => 1.492,
        'c' => 2.202,
        'd' => 4.253,
        'e' => 11.162,
        'f' => 2.228,
        'g' => 2.015,
        'h' => 6.094,
        'i' => 7.546,
        'j' => 0.153,
        'k' => 1.292,
        'l' => 4.025,
        'm' => 2.406,
        'n' => 6.749,
        'o' => 7.507,
        'p' => 1.929,
        'q' => 0.095,
        'r' => 7.587,
        's' => 6.327,
        't' => 9.356,
        'u' => 2.758,
        'v' => 0.978,
        'w' => 2.560,
        'x' => 0.150,
        'y' => 1.974,
        'z' => 0.077,
        ' ' => 1.3000,
        '!' => 0.000,
        '\'' => 0.000,
        ',' => 0.000,
        '.' => 0.000,
        ':' => 0.000,
        ';' => 0.000,
        '\n' => 0.000,
        _ => -10.000,
    }
}

#[cfg(test)]
// Converts uint8 vector to total frequency score.
pub fn bytes_to_score(vec: &Vec<u8>) -> f32 {
    vec.iter().fold(0.000, |sum, x| {
        sum + char_to_score(char::from(*x).to_ascii_lowercase())
    })
}

#[cfg(test)]
// Computes the bitwise Hamming distance between x and y.
pub fn compute_edit_distance(x: Vec<u8>, y: Vec<u8>) -> u64 {
    x.iter()
        .zip(y)
        .fold(0, |distance, (a, b)| distance + (a ^ b).count_ones() as u64)
}

#[test]
fn compute_edit_distance_test_1() {
    let s1 = String::from("this is a test");
    let s2 = String::from("wokka wokka!!!");
    let expected_result = 37;
    assert_eq!(
        expected_result,
        compute_edit_distance(s1.into_bytes(), s2.into_bytes())
    );
}
