#[cfg(test)]
// MIME base64 charset.
const BASE64_CHARS: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

#[cfg(test)]
// Converts a base64 string to bytes.
pub fn base64_to_bytes(mut base64: String) -> Vec<u8> {
    let mut output = Vec::new();

    // Replaces incoming padding with zero pad.
    base64 = base64.replace("=", "A");

    // Remove non-ASCII characters like newlines.
    base64.retain(|c| BASE64_CHARS.contains(&c));

    // Converts each chunk of 4 6-bit indexes into original three-bit ASCII characters.
    for chunk in base64.into_bytes().chunks(4) {
        let mut n = BASE64_CHARS
            .iter()
            .position(|&c| c == char::from(chunk[0]))
            .unwrap()
            << 18;
        if chunk.len() > 1 {
            n = n
                + (BASE64_CHARS
                    .iter()
                    .position(|&c| c == char::from(chunk[1]))
                    .unwrap()
                    << 12)
        }
        if chunk.len() > 2 {
            n = n
                + (BASE64_CHARS
                    .iter()
                    .position(|&c| c == char::from(chunk[2]))
                    .unwrap()
                    << 6)
        }
        if chunk.len() > 3 {
            n = n + BASE64_CHARS
                .iter()
                .position(|&c| c == char::from(chunk[3]))
                .unwrap();
        }
        output.append(&mut vec![
            ((n >> 16) & 255) as u8,
            ((n >> 8) & 255) as u8,
            (n & 255) as u8,
        ]);
    }

    // Trims trailing zeros.
    while output[output.len() - 1] == 0 {
        output = output[0..output.len() - 1].to_vec();
    }

    return output;
}

#[cfg(test)]
// Converts bytes to a base64 string.
pub fn bytes_to_base64(mut bytes: Vec<u8>) -> String {
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
// Encodes a uint8 vector into a hex string.
pub fn bytes_to_hex(bytes: Vec<u8>) -> String {
    let hex_strings: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    return hex_strings.join("").to_ascii_lowercase();
}

#[cfg(test)]
// Decodes a hex string into a uint8 vector.
pub fn hex_to_bytes(s: &String) -> Vec<u8> {
    let result = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect();
    let result = match result {
        Ok(result) => result,
        Err(error) => panic!("Failed to decode hex string: {:?}", error),
    };
    return result;
}

#[cfg(test)]
pub struct UserProfile {
    pub email: String,
    pub uid: u8,
    pub role: String,
}

#[cfg(test)]
// Encodes a user profile given an email address.
pub fn profile_for(input: &String) -> String {
    let email = input.replace(&['&', '='][..], "");
    let user_profile = UserProfile {
        email: email,
        uid: 10,
        role: String::from("user"),
    };
    let encoded_profile = String::from(format!(
        "email={}&uid={}&role={}",
        user_profile.email, user_profile.uid, user_profile.role
    ));
    return encoded_profile;
}

#[test]
fn base64_to_bytes_test_1() {
    let base64 = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    let expected_result =
    hex_to_bytes(&String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"));
    assert_eq!(expected_result, base64_to_bytes(base64));
}
