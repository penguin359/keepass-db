use std::num::Wrapping;

pub struct ArcFourVariant {
    initial_i: Wrapping<u8>,
    initial_j: Wrapping<u8>,
    initial: [Wrapping<u8>; 256],
    i: Wrapping<u8>,
    j: Wrapping<u8>,
    state:   [Wrapping<u8>; 256],
}

impl ArcFourVariant {
    pub fn new(key: &[u8]) -> Self {
        let mut rc4 = Self {
            initial_i: Wrapping(0),
            initial_j: Wrapping(0),
            initial: [Wrapping(0); 256],
            i: Wrapping(0),
            j: Wrapping(0),
            state: [Wrapping(0); 256],
        };

        for i in 0..256 {
            rc4.state[i] = Wrapping(i as u8);
        }

        let mut j = Wrapping(0u8);
        for i in 0..256 {
            j += rc4.state[i] + Wrapping(key[i % key.len()]);
            // ArcFourVariant as developed by KeePass deviates from RC4 here
            //rc4.state.swap(i, j.0 as usize);
            rc4.state.swap(0, j.0 as usize);
        }

        rc4.gen(&mut [0; 512]);
        rc4.initial = rc4.state;
        rc4.initial_i = rc4.i;
        rc4.initial_j = rc4.j;
        //eprintln!("State: {}, {}, {:#04x?}", rc4.i.0, rc4.j.0, rc4.state);
        // eprintln!("First initial: {:#04X?}", rc4.initial);

        return rc4;
    }

    pub fn gen(&mut self, buf: &mut [u8]) {
        //let mut j = Wrapping(0);
        for x in 0..buf.len() {
            self.i += 1;
            self.j += self.state[self.i.0 as usize];
            self.state.swap(self.i.0 as usize, self.j.0 as usize);
            let t = self.state[self.i.0 as usize] + self.state[self.j.0 as usize];
            let t = self.state[t.0 as usize];
            //eprintln!("K: {:#04X?}", t.0);
            buf[x] ^= t.0;
        }
    }

    pub fn seek(&mut self, pos: usize) {
        // eprintln!("Initial: {:#04X?}", self.initial);
        self.i = self.initial_i;
        self.j = self.initial_j;
        self.state = self.initial;
        self.gen(&mut vec![0; pos]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4() {
        let key = [ 0xDB, 0x6F, 0xC5, 0xE8, 0xFC, 0x6B, 0x3D, 0x95, 0x49, 0x7D, 0x52, 0xE4, 0xB2, 0x15, 0xED, 0x7D,
                    0xE0, 0x48, 0x24, 0xC1, 0x2F, 0x52, 0xF8, 0x87, 0x77, 0x62, 0xD0, 0x9C, 0x27, 0x6B, 0x37, 0x75, ];

        // Plaintext is Notes
        let mut ciphertext = [ 0x90, 0x21, 0xA1, 0x07, 0x53, ];
        let expected = [ 0x4E, 0x6F, 0x74, 0x65, 0x73, ];

        // Plaintext is Password
        let mut ciphertext2 = [ 0x43, 0xE2, 0x7F, 0xA2, 0x1A, 0x75, 0x67, 0xEE, ];
        let expected2 = [ 0x50, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, ];

        let mut rc4 = ArcFourVariant::new(&key);
        rc4.gen(&mut ciphertext);
        assert_eq!(ciphertext, expected, "Initial decrypt");
        rc4.gen(&mut ciphertext2);
        assert_eq!(ciphertext2, expected2, "Final decrypt");
    }
}
