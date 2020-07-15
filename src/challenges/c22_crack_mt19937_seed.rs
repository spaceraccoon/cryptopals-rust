#[cfg(test)]
use crate::utils::{rng::MersenneTwister, rng::STATE_SIZE};
#[cfg(test)]
use rand::{thread_rng, Rng};

#[cfg(test)]
// Brute forces all possible seeds to find matching seed with first output.
fn crack_seed(output: u32) -> u32 {
    for i in 0..u32::MAX {
        let mut mt = MersenneTwister {
            state: vec![0; STATE_SIZE],
            index: 0,
        };
        mt.init(i);
        if output == mt.next().unwrap() {
            return i;
        }
    }
    panic!("No seed found!");
}

#[test]
fn test_1() {
    let mut rng = rand::thread_rng();
    // Uses u16 seed to lower cracking time.
    let seed: u16 = rng.gen();

    let mut mt = MersenneTwister {
        state: vec![0; STATE_SIZE],
        index: 0,
    };

    mt.init(u32::from(seed));
    let output = mt.next().unwrap();
    let cracked_seed = crack_seed(output);
    assert_eq!(u32::from(seed), cracked_seed);
}
