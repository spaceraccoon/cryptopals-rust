#[cfg(test)]
use crate::utils::{rng::MersenneTwister, rng::STATE_SIZE};
#[cfg(test)]
use rand::{thread_rng, Rng};

#[cfg(test)]
// Undos right shift with shifting mask.
fn undo_right(mut val: u32, shift: u32) -> u32 {
    let mut original = val;
    for _ in 0..32 / shift {
        val >>= shift;
        original ^= val;
    }
    return original;
}

#[cfg(test)]
// Undos left shift with shifting mask.
fn undo_left(val: u32, shift: u32, constant: u32) -> u32 {
    let mut original = val;
    for _ in 0..32 / shift {
        original = val ^ (original << shift & constant);
    }
    return original;
}

#[cfg(test)]
// Reverses the tempering of output back into original state values.
fn untemper(outputs: &Vec<u32>) -> Vec<u32> {
    let mut untempered = outputs.clone();
    for i in 0..STATE_SIZE {
        // Refer to https://occasionallycogent.com/inverting_the_mersenne_temper/index.html
        untempered[i] = undo_right(untempered[i], 18);
        untempered[i] = undo_left(untempered[i], 15, 0xefc6_0000);
        untempered[i] = undo_left(untempered[i], 7, 0x9d2c_5680);
        untempered[i] = undo_right(untempered[i], 11);
    }
    return untempered;
}

#[test]
fn test_1() {
    let mut rng = rand::thread_rng();
    let seed: u32 = rng.gen();

    let mut mt = MersenneTwister {
        state: vec![0; STATE_SIZE],
        index: 0,
    };

    mt.init(u32::from(seed));
    let outputs = mt.take(STATE_SIZE).collect::<Vec<u32>>();

    // Generates cloned state by untempering output.
    let cloned_state = untemper(&outputs);
    let cloned_mt = MersenneTwister {
        state: cloned_state,
        index: 0,
    };
    let cloned_outputs = cloned_mt.take(STATE_SIZE).collect::<Vec<u32>>();
    assert_eq!(outputs, cloned_outputs);
}
