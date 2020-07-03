#[cfg(test)]
use std::num::ParseIntError;

#[cfg(test)]
// Decodes a hex string into a uint8 vector.
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

#[cfg(test)]
// Encodes a uint8 vector into a hex string.
pub fn bytes_to_hex(bytes: Vec<u8>) -> String {
    let hex_strings: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    return hex_strings.join("").to_ascii_lowercase();
}

#[cfg(test)]
pub fn bytes_to_base64(mut bytes: Vec<u8>) -> String {
    const BASE64_CHARS: [char; 64] = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
        '2', '3', '4', '5', '6', '7', '8', '9', '+', '-',
    ];

    let mut output = String::new();
    let length = bytes.len();
    let remainder = length % 3;
    let mut padding = String::new();

    // Add a right zero pad to make this string a multiple of 3 characters.
    if remainder > 0 {
        let mut zero_vec = vec![0; 3 - remainder];
        bytes.append(&mut zero_vec);
        padding = "=".repeat(3 - remainder);
    }

    // Increment over the length of the string, three characters at a time.
    for x in (0..length).step_by(3) {
        // These three 8-bit (ASCII) characters become one 24-bit number.
        let n =
            (u32::from(bytes[x]) << 16) + (u32::from(bytes[x + 1]) << 8) + u32::from(bytes[x + 2]);
        // This 24-bit number gets separated into four 6-bit numbers.
        let n0 = ((n >> 18) & 63) as usize;
        let n1 = ((n >> 12) & 63) as usize;
        let n2 = ((n >> 6) & 63) as usize;
        let n3 = (n & 63) as usize;

        // Those four 6-bit numbers are used as indices into the base64 character list.
        output.push(BASE64_CHARS[n0]);
        output.push(BASE64_CHARS[n1]);
        output.push(BASE64_CHARS[n2]);
        output.push(BASE64_CHARS[n3]);
    }

    // Add the actual padding string, after removing the zero pad.
    if remainder > 0 {
        output = String::from(&output[..(output.len() - 3 + remainder)]) + &padding;
    }
    return output;
}

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
        ' ' => 0.000,
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
    return vec.iter().fold(0.000, |sum, x| {
        sum + char_to_score(char::from(*x).to_ascii_lowercase())
    });
}
