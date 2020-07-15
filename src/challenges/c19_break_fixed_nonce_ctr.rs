#[cfg(test)]
use crate::utils::{
    convert::base64_to_bytes, decrypt::guess_repeating_key, decrypt::AES_BLOCK_SIZE,
    encrypt::encrypt_aes_ctr, encrypt::repeating_key_xor,
};
#[cfg(test)]
use rand::{thread_rng, Rng};
#[cfg(test)]
use std::{fs::File, io::BufRead, io::BufReader};

#[test]
fn test_1() {
    let mut rng = thread_rng();
    // Generates random key.
    let key: Vec<u8> = (0..AES_BLOCK_SIZE).map(|_| rng.gen::<u8>()).collect();

    // Encrypts plaintexts.
    let file_1 = File::open("resources/19.txt").unwrap();
    let lines_1: Vec<Vec<u8>> = BufReader::new(file_1)
        .lines()
        .map(|line| encrypt_aes_ctr(&base64_to_bytes(line.unwrap()), &key, 0, AES_BLOCK_SIZE))
        .collect();
    let file_2 = File::open("resources/20.txt").unwrap();
    let lines_2: Vec<Vec<u8>> = BufReader::new(file_2)
        .lines()
        .map(|line| encrypt_aes_ctr(&base64_to_bytes(line.unwrap()), &key, 0, AES_BLOCK_SIZE))
        .collect();
    let ciphertexts = [lines_1, lines_2].concat();
    // Truncates ciphertexts to common length.
    let smallest_length = ciphertexts.iter().map(|c| c.len()).min().unwrap();
    let ciphertext: Vec<u8> = ciphertexts
        .iter()
        .flat_map(|ciphertext| &ciphertext[..smallest_length])
        .cloned()
        .collect();
    let key = guess_repeating_key(&ciphertext, smallest_length);
    let plaintext = repeating_key_xor(ciphertext, key);
    let expected_result = base64_to_bytes(String::from("SSBoYXZlIG1ldCB0aGVtIGF0IGNDb21pbmcgd2l0aCB2aXZpZCBmYUZyb20gY291bnRlciBvciBkZXNrRWlnaHRlZW50aC1jZW50dXJ5IGhJIGhhdmUgcGFzc2VkIHdpdGggYU9yIHBvbGl0ZSBtZWFuaW5nbGVzT3IgaGF2ZSBsaW5nZXJlZCBhd2hQb2xpdGUgbWVhbmluZ2xlc3Mgd0FuZCB0aG91Z2h0IGJlZm9yZSBJT2YgYSBtb2NraW5nIHRhbGUgb3JUbyBwbGVhc2UgYSBjb21wYW5pb0Fyb3VuZCB0aGUgZmlyZSBhdCB0QmVpbmcgY2VydGFpbiB0aGF0IHRCdXQgbGl2ZWQgd2hlcmUgbW90bEFsbCBjaGFuZ2VkLCBjaGFuZ2VkQSB0ZXJyaWJsZSBiZWF1dHkgaXNUaGF0IHdvbWFuJ3MgZGF5cyB3ZUluIGlnbm9yYW50IGdvb2Qgd2lsSGVyIG5pZ2h0cyBpbiBhcmd1bWVVbnRpbCBoZXIgdm9pY2UgZ3Jld1doYXQgdm9pY2UgbW9yZSBzd2VlV2hlbiB5b3VuZyBhbmQgYmVhdXRTaGUgcm9kZSB0byBoYXJyaWVyc1RoaXMgbWFuIGhhZCBrZXB0IGEgQW5kIHJvZGUgb3VyIHdpbmdlZCBUaGlzIG90aGVyIGhpcyBoZWxwZVdhcyBjb21pbmcgaW50byBoaXMgSGUgbWlnaHQgaGF2ZSB3b24gZmFTbyBzZW5zaXRpdmUgaGlzIG5hdFNvIGRhcmluZyBhbmQgc3dlZXQgVGhpcyBvdGhlciBtYW4gSSBoYWRBIGRydW5rZW4sIHZhaW4tZ2xvckhlIGhhZCBkb25lIG1vc3QgYml0VG8gc29tZSB3aG8gYXJlIG5lYXJZZXQgSSBudW1iZXIgaGltIGluIEhlLCB0b28sIGhhcyByZXNpZ25lSW4gdGhlIGNhc3VhbCBjb21lZHlIZSwgdG9vLCBoYXMgYmVlbiBjaFRyYW5zZm9ybWVkIHV0dGVybHk6QSB0ZXJyaWJsZSBiZWF1dHkgaXNJJ20gcmF0ZWQgIlIiLi4udGhpc0N1eiBJIGNhbWUgYmFjayB0byBhQnV0IGRvbid0IGJlIGFmcmFpZCBZYSB0cmVtYmxlIGxpa2UgYSBhbFN1ZGRlbmx5IHlvdSBmZWVsIGxpTXVzaWMncyB0aGUgY2x1ZSwgd2hIYXZlbid0IHlvdSBldmVyIGhlYURlYXRoIHdpc2gsIHNvIGNvbWUgRnJpZGF5IHRoZSB0aGlydGVlbnRUaGlzIGlzIG9mZiBsaW1pdHMsIFRlcnJvciBpbiB0aGUgc3R5bGVzRm9yIHRob3NlIHRoYXQgb3Bwb3NXb3JzZSB0aGFuIGEgbmlnaHRtYUZsYXNoYmFja3MgaW50ZXJmZXJlVGhlbiB0aGUgYmVhdCBpcyBoeXNTb29uIHRoZSBseXJpY2FsIGZvck1DJ3MgZGVjYXlpbmcsIGN1eiB0VGhlIGZpZW5kIG9mIGEgcmh5bWVNZWxvZGllcy11bm1ha2FibGUsIEkgYmxlc3MgdGhlIGNoaWxkLCB0SGF6YXJkb3VzIHRvIHlvdXIgaGVTaGFrZSAndGlsbCB5b3VyIGNsZUlmIG5vdCwgbXkgc291bCdsbCByQ3V6IHlvdXIgYWJvdXQgdG8gc2VMeXJpY3Mgb2YgZnVyeSEgQSBmZU1ha2Ugc3VyZSB0aGUgc3lzdGVtWW91IHdhbnQgdG8gaGVhciBzb21UaGVuIG5vbmNoYWxhbnRseSB0ZUFuZCBJIGRvbid0IGNhcmUgaWYgUHJvZ3JhbSBpbnRvIHRoZSBzcGVNdXNpY2FsIG1hZG5lc3MgTUMgZU9wZW4geW91ciBtaW5kLCB5b3UgQmF0dGxlJ3MgdGVtcHRpbmcuLi5Zb3UgdGhpbmsgeW91J3JlIHJ1Zkkgd2FrZSB5YSB3aXRoIGh1bmRyTm92b2NhaW4gZWFzZSB0aGUgcGFZbyBSYWtpbSwgd2hhdCdzIHVwP1dlbGwsIGNoZWNrIHRoaXMgb3V0S2FyYSBMZXdpcyBpcyBvdXIgYWdPa2F5LCBzbyB3aG8gd2Ugcm9sbENoZWNrIHRoaXMgb3V0LCBzaW5jSSB3YW5uYSBoZWFyIHNvbWUgb2ZUaGlua2luJyBvZiBhIG1hc3RlclNvIEkgZGlnIGludG8gbXkgcG9jU28gSSBzdGFydCBteSBtaXNzaW9JIG5lZWQgbW9uZXksIEkgdXNlZEkgdXNlZCB0byByb2xsIHVwLCB0QnV0IG5vdyBJIGxlYXJuZWQgdG9TZWFyY2ggZm9yIGEgbmluZSB0b1NvIEkgd2FsayB1cCB0aGUgc3RyQSBwZW4gYW5kIGEgcGFwZXIsIGFGaXNoLCB3aGljaCBpcyBteSBmYSdDdXogSSBkb24ndCBsaWtlIHRvU28gbm93IHRvIHRlc3QgdG8gc2VSYWtpbSwgY2hlY2sgdGhpcyBvdSdDYXVzZSBteSBnaXJsIGlzIGRlWW8sIEkgaGVhciB3aGF0IHlvdSdBbmQgY291bnQgb3VyIG1vbmV5IFR1cm4gZG93biB0aGUgYmFzcyBkQW5kIHdlIG91dHRhIGhlcmUgLyA="));
    assert_eq!(expected_result, plaintext);
}
