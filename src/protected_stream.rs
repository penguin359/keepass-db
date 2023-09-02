use num_traits::{FromPrimitive, ToPrimitive};

use hex_literal::hex;

use ring::digest::{Context, SHA256, SHA512};
use salsa20::cipher::{KeyIvInit, StreamCipher};
use salsa20::Key as Salsa20_Key;
use salsa20::Salsa20;

use generic_array::GenericArray;
// use chacha20::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use chacha20::ChaCha20;
use chacha20::cipher::StreamCipherSeek;

#[derive(FromPrimitive, ToPrimitive)]
enum CipherType {
    Null = 0,
    RC4 = 1,
    Salsa20 = 2,
    ChaCha20 = 3,
}

enum CipherValue {
    Null,
    Salsa20(Salsa20),
    ChaCha20(ChaCha20),
}

impl CipherValue {
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        match self {
            Self::Null => (),
            Self::Salsa20(c) => c.apply_keystream(buf),
            Self::ChaCha20(c) => c.apply_keystream(buf),
        }
    }

    pub fn apply_keystream_pos(&mut self, buf: &mut [u8], pos: usize) {
        match self {
            Self::Null => (),
            Self::Salsa20(c) => c.try_seek(pos as u64).unwrap(),
            Self::ChaCha20(c) => c.try_seek(pos as u64).unwrap(),
        }
        self.apply_keystream(buf);
    }
}

// struct StreamCipher {
// }

#[derive(Debug)]
enum Error {
    InvalidCipher(u32),
}

fn new_stream(cipher: u32, key: &[u8]) -> Result<CipherValue, Error> {
    let r#type = CipherType::from_u32(cipher).ok_or(Error::InvalidCipher(cipher))?;
    Ok(match r#type {
        CipherType::Null => CipherValue::Null,
        CipherType::RC4 => unimplemented!(),
        CipherType::Salsa20 => {
            let nonce = hex!("E830094B97205D2A");
            let mut context = Context::new(&SHA256);
            context.update(key);
            let p2_key = context.finish().as_ref().to_owned();
            let key = Salsa20_Key::from_slice(&p2_key[0..32]);
            CipherValue::Salsa20(Salsa20::new(&key, &nonce.into()))
        }
        CipherType::ChaCha20 => {
            let mut context = Context::new(&SHA512);
            context.update(key);
            let p2_key = context.finish().as_ref().to_owned();
            let key = GenericArray::from_slice(&p2_key[0..32]);
            let nonce = GenericArray::from_slice(&p2_key[32..32 + 12]);
            CipherValue::ChaCha20(ChaCha20::new(&key, &nonce))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null() {
        let mut c = new_stream(0, &[]).unwrap();
        let mut ciphertext = [0x61, 0x62, 0x63, 0x64];
        let expected = "abcd";
        c.apply_keystream(&mut ciphertext);
        let actual = String::from_utf8(ciphertext.to_vec()).expect("Valid utf-8");
        assert_eq!(actual, expected);

        c.apply_keystream_pos(&mut ciphertext, 10);
        let actual = String::from_utf8(ciphertext.to_vec()).expect("Valid utf-8");
        assert_eq!(actual, expected);

        c.apply_keystream_pos(&mut ciphertext, 0);
        let actual = String::from_utf8(ciphertext.to_vec()).expect("Valid utf-8");
        assert_eq!(actual, expected);
    }

    const CHACHA20_KEY: [u8; 64] = hex!(
        "47d3d820a2eb2b5b0b57e3397875c5fb"
        "ef0676f0f9425b5f0a9ba9f32060134e"
        "9a612a5b3be2366f0fab2c8f16980760"
        "c82e194a800c0c60c2f9000d5a64daab");

    const CHACHA20_OFFSET: usize = 0;
    const CHACHA20_CIPHERTEXT: [u8; 8] = [
        0x07,
        0x69,
        0xE8,
        0xD6,
        0x95,
        0x5F,
        0x4D,
        0x82,
    ];
    const CHACHA20_PLAINTEXT: &str = "Password";

    const CHACHA20_CIPHERTEXT2: [u8; 10] = [
        0x3C,
        0xBC,
        0xB1,
        0xB5,
        0x08,
        0xD3,
        0x1A,
        0x65,
        0xD0,
        0x52,
    ];
    const CHACHA20_OFFSET2: usize = 94;
    const CHACHA20_PLAINTEXT2: &str = "don't tell";

    #[test]
    fn test_chacha20() {
        let mut c = new_stream(3, &CHACHA20_KEY).unwrap();
        let mut ciphertext = CHACHA20_CIPHERTEXT.clone();
        let expected = CHACHA20_PLAINTEXT;
        c.apply_keystream(&mut ciphertext);
        let actual = String::from_utf8(ciphertext.to_vec()).expect("Valid utf-8");
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_chacha20_offsets() {
        let mut c = new_stream(3, &CHACHA20_KEY).unwrap();
        let mut ciphertext = CHACHA20_CIPHERTEXT2.clone();
        let expected = CHACHA20_PLAINTEXT2;
        c.apply_keystream_pos(&mut ciphertext, CHACHA20_OFFSET2);
        let actual = String::from_utf8(ciphertext.to_vec()).expect("Valid utf-8");
        assert_eq!(actual, expected);

        let mut c = new_stream(3, &CHACHA20_KEY).unwrap();
        let mut ciphertext = CHACHA20_CIPHERTEXT.clone();
        let expected = CHACHA20_PLAINTEXT;
        c.apply_keystream_pos(&mut ciphertext, CHACHA20_OFFSET);
        let actual = String::from_utf8(ciphertext.to_vec()).expect("Valid utf-8");
        assert_eq!(actual, expected);
    }

    const SALSA20_KEY: [u8; 32] = hex!(
        "578b10cfc954562053f926dfdbfa26d1"
        "7edc7c7e5f7bedeff88ecc22a8469a08");

    const SALSA20_OFFSET: usize = 0;
    const SALSA20_CIPHERTEXT: [u8; 6] = [
        0x10,
        0xE8,
        0xFC,
        0x22,
        0xCF,
        0xE4,
    ];
    const SALSA20_PLAINTEXT: &str = "hidden";

    const SALSA20_CIPHERTEXT2: [u8; 5] = [
        0x70,
        0x8C,
        0x76,
        0xA0,
        0xF8,
    ];
    const SALSA20_OFFSET2: usize = 12;
    const SALSA20_PLAINTEXT2: &str = "value";

    #[test]
    fn test_salsa20() {
        let mut c = new_stream(2, &SALSA20_KEY).unwrap();
        let mut ciphertext = SALSA20_CIPHERTEXT.clone();
        let expected = SALSA20_PLAINTEXT;
        c.apply_keystream(&mut ciphertext);
        let actual = String::from_utf8(ciphertext.to_vec()).expect("Valid utf-8");
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_salsa20_offsets() {
        let mut c = new_stream(2, &SALSA20_KEY).unwrap();
        let mut ciphertext = SALSA20_CIPHERTEXT2.clone();
        let expected = SALSA20_PLAINTEXT2;
        c.apply_keystream_pos(&mut ciphertext, SALSA20_OFFSET2);
        let actual = String::from_utf8(ciphertext.to_vec()).expect("Valid utf-8");
        assert_eq!(actual, expected);

        let mut c = new_stream(2, &SALSA20_KEY).unwrap();
        let mut ciphertext = SALSA20_CIPHERTEXT.clone();
        let expected = SALSA20_PLAINTEXT;
        c.apply_keystream_pos(&mut ciphertext, SALSA20_OFFSET);
        let actual = String::from_utf8(ciphertext.to_vec()).expect("Valid utf-8");
        assert_eq!(actual, expected);
    }
}
