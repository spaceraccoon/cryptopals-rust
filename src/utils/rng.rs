#[cfg(test)]
pub const STATE_SIZE: usize = 624;
#[cfg(test)]
pub const F_MY19937: u32 = 1812433253;

#[cfg(test)]
pub struct MersenneTwister {
    pub state: Vec<u32>,
    pub index: usize,
}

#[cfg(test)]
impl MersenneTwister {
    // Initializes state.
    pub fn init(&mut self, seed: u32) {
        self.state[0] = seed;
        for i in 1..STATE_SIZE {
            self.state[i] = (self.state[i - 1] ^ (self.state[i - 1] >> 30))
                .wrapping_mul(F_MY19937)
                .wrapping_add(i as u32);
        }
    }

    // Generates the next n values from the series x_i.
    pub fn twist(&mut self) {
        for i in 0..STATE_SIZE {
            let x =
                (self.state[i] & 0x8000_0000) + (self.state[(i + 1) % STATE_SIZE] & 0x7fff_ffff);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                // lowest bit of x is 1
                x_a ^= 0x9908_b0df;
            }
            self.state[i] = self.state[(i + 397) % STATE_SIZE] ^ x_a;
        }
        self.index = 0;
    }
}

#[cfg(test)]
impl Iterator for MersenneTwister {
    type Item = u32;

    // Extract a tempered value based on MT[index] calling twist() every n numbers.
    fn next(&mut self) -> Option<u32> {
        if self.index >= STATE_SIZE {
            if self.index > STATE_SIZE {
                self.init(5489); // Seed with constant value; 5489 is used in reference C code[51]
            }
            self.twist();
        }
        let mut y = self.state[self.index];
        y ^= (y >> 11) & 0xffff_ffff;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;

        self.index += 1;
        return Some(y);
    }
}
