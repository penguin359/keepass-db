use std::convert::TryInto;
use std::io;
use std::io::prelude::*;
use std::io::Cursor;
use std::collections::HashMap;

use uuid::{Uuid};
use openssl::symm::{decrypt, Cipher, Crypter, Mode};
use ring::digest::{Context, SHA256, SHA512};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::{KDF_AES_KDBX3, MapValue};

mod argon2;
pub use argon2::*;

pub const KDF_PARAM_UUID: &str = "$UUID"; // UUID, KDF used to derive master key
pub const KDF_PARAM_SALT: &str = "S"; // Byte[], Generates 32 bytes, required
pub const KDF_PARAM_ROUNDS: &str = "R"; // Byte[], Generates 32 bytes, required
pub const KDF_PARAM_PARALLELISM: &str = "P"; // UInt32, Default, required
pub const KDF_PARAM_MEMORY: &str = "M"; // UInt64, Default, required
pub const KDF_PARAM_ITERATIONS: &str = "I"; // UInt64, Default, required
pub const KDF_PARAM_VERSION: &str = "V"; // UInt32, Min/Max, Default Max, required
const _KDF_PARAM_SECRET_KEY: &str = "K"; // Byte[]
const _KDF_PARAM_ASSOC_DATA: &str = "A"; // Byte[]

pub trait Kdf {
    fn uuid(&self) -> Uuid;
    fn randomize(&mut self);
    fn transform_key(&self, composite_key: &[u8]) -> io::Result<Vec<u8>>;
    fn save(&self, custom_data: &mut HashMap<String, MapValue>);
}

pub struct AesKdf {
    salt: [u8; 32],
    rounds: u64,
}

impl AesKdf {
    pub fn load(custom_data: &HashMap<String, MapValue>) -> io::Result<Self> {
        // let salt = &custom_data[KDF_PARAM_SALT];
        // let mut c = custom_data[KDF_PARAM_ROUNDS];
        match (&custom_data[KDF_PARAM_SALT], &custom_data[KDF_PARAM_ROUNDS]) {
            (MapValue::ByteArray(ref salt), MapValue::UInt64(rounds)) => Ok(AesKdf {
                salt: salt.clone().try_into().unwrap(), /*From::<Vec<u8>>::try_into(salt.clone()).unwrap()*/
                rounds: *rounds,
            }),
            _ => Err(io::Error::new(io::ErrorKind::Unsupported, "Bad rounds")),
        }
    }
}

impl Kdf for AesKdf {
    fn uuid(&self) -> Uuid {
        KDF_AES_KDBX3
    }

    fn randomize(&mut self) {
        unimplemented!("Can't randomize yet")
    }

    fn save(&self, custom_data: &mut HashMap<String, MapValue>) {
        custom_data.insert(KDF_PARAM_ROUNDS.to_string(), MapValue::UInt64(self.rounds));
        custom_data.insert(
            KDF_PARAM_SALT.to_string(),
            MapValue::ByteArray(self.salt.into()),
        );
    }

    fn transform_key(&self, composite_key: &[u8]) -> io::Result<Vec<u8>> {
        println!("Calculating transformed key ({})", self.rounds);

        let mut transform_key = composite_key.to_owned();
        let cipher = Cipher::aes_256_ecb();
        let mut c = Crypter::new(cipher, Mode::Encrypt, &self.salt, None)?;
        for _ in 0..cipher.block_size() {
            transform_key.push(0);
        }
        let mut out = vec![0; 16 + 16 + cipher.block_size()];
        c.pad(false);
        for _ in 0..self.rounds {
            c.update(&transform_key[0..32], &mut out)?;
            let temp = transform_key;
            transform_key = out;
            out = temp;
        }
        transform_key.truncate(32);
        let mut context = Context::new(&SHA256);
        context.update(&transform_key);
        Ok(context.finish().as_ref().to_owned())
    }
}

impl Default for AesKdf {
    fn default() -> Self {
        Self {
            salt: [0; 32],
            rounds: 60000,
        }
    }
}

pub fn transform_aes_kdf(
    composite_key: &[u8],
    custom_data: &HashMap<String, Vec<u8>>,
) -> io::Result<Vec<u8>> {
    let transform_seed = &custom_data[KDF_PARAM_SALT];
    let mut c = Cursor::new(&custom_data[KDF_PARAM_ROUNDS]);
    let transform_round = c.read_u64::<LittleEndian>()?;

    println!("Calculating transformed key ({})", transform_round);

    let mut transform_key = composite_key.to_owned();
    let cipher = Cipher::aes_256_ecb();
    let mut c = Crypter::new(cipher, Mode::Encrypt, transform_seed, None)?;
    for _ in 0..cipher.block_size() {
        transform_key.push(0);
    }
    let mut out = vec![0; 16 + 16 + cipher.block_size()];
    c.pad(false);
    for _ in 0..transform_round {
        c.update(&transform_key[0..32], &mut out)?;
        let temp = transform_key;
        transform_key = out;
        out = temp;
    }
    transform_key.truncate(32);
    let mut context = Context::new(&SHA256);
    context.update(&transform_key);
    Ok(context.finish().as_ref().to_owned())
}
