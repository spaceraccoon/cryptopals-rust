#[cfg(test)]
use crate::utils::{rng::MersenneTwister, rng::STATE_SIZE};

#[test]
fn test_1() {
    let mut mt = MersenneTwister {
        state: vec![0; STATE_SIZE],
        index: 0,
    };
    let expected_result: Vec<u32> = vec![
        4194449, 1284266036, 2640547639, 2425321445, 1773925551, 2456075846, 2087774401, 571047336,
        637749748, 1141847822,
    ];
    mt.init(1);
    assert_eq!(expected_result, mt.take(10).collect::<Vec<u32>>());
}
