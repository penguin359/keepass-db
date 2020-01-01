extern crate hex;
extern crate byteorder;
extern crate base64;
extern crate uuid;
extern crate ring;
extern crate rpassword;
extern crate openssl;
extern crate flate2;
extern crate sxd_document;
extern crate sxd_xpath;
extern crate chrono;
#[cfg(feature = "rust-argon2")]
extern crate argon2;
#[cfg(feature = "argonautica")]
extern crate argonautica;
extern crate chacha20;
#[macro_use]
extern crate log;

use std::io::Cursor;
use std::env;
use std::process;
use std::fs::File;
use std::io::{self, SeekFrom};
use std::io::prelude::*;
use std::collections::HashMap;

//use hex::ToHex;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use base64::decode;
use uuid::{Builder, Uuid};
use ring::digest::{Context, SHA256, SHA512};
use ring::hmac;
use rpassword::read_password;
use openssl::symm::{decrypt, Crypter, Cipher, Mode};
use flate2::read::GzDecoder;
use sxd_document::parser;
use sxd_xpath::{evaluate_xpath, Context as XPathContext, Factory, Value};
use chrono::prelude::*;
use chacha20::ChaCha20;
use chacha20::stream_cipher::generic_array::GenericArray;
use chacha20::stream_cipher::{NewStreamCipher, SyncStreamCipher};

#[cfg(feature = "rust-argon2")]
use argon2::{Config, ThreadMode, Variant, Version};
#[cfg(feature = "argonautica")]
use argonautica::{Hasher, config::{Variant, Version}};

//use hex::FromHex;

#[cfg(test)]
mod tests {
    use hex::FromHex;

    use super::*;

    // Simple password is asdf
    const PASSWORD_SIMPLE : &str = "61736466";

    // Composite key generated from simple, password-only lock
    const COMPOSITE_KEY_PASSWORD : &str =
        "fe9a32f5b565da46af951e4aab23c24b8c1565eb0b6603a03118b7d225a21e8c";

    #[test]
    fn test_user_password() {
        let data = Vec::from_hex(PASSWORD_SIMPLE).unwrap();
        let mut key = Key::new();
        key.set_user_password(data);
        assert_eq!(key.composite_key(), Vec::from_hex(COMPOSITE_KEY_PASSWORD).unwrap());
    }

    #[test]
    #[ignore]
    #[cfg(feature = "rust-argon2")]
    fn test_argon2() {
        let password = b"password";
        let salt = b"othersalt";
        let config = Config {
            variant: Variant::Argon2d,
            version: Version::Version13,
            mem_cost: 65536,
            time_cost: 10,
            lanes: 4,
            thread_mode: ThreadMode::Parallel,
            secret: &[],
            ad: &[],
            hash_length: 32
        };
        let hash = argon2::hash_encoded(password, salt, &config).unwrap();
        let matches = argon2::verify_encoded(&hash, password).unwrap();
        assert!(matches);
    }

    fn make_u32(value: u32) -> Vec<u8> {
        let out = vec![0; 4];
        let mut cursor = Cursor::new(out);
        cursor.write_u32::<LittleEndian>(value).unwrap();
        cursor.into_inner()
    }

    const ARGON2_HASH : &str = "4eb4d1f66ae3c88d85445fb49ae7c4a8fd51eeaa132c53cb8b37610f02569371";

    #[test]
    #[ignore]
    fn test_argon2_kdf() {
        //let data = Vec::from_hex(PASSWORD_SIMPLE).unwrap();
        //let mut key = Key::new();
        //key.set_user_password(data);
        //let composite_key = Vec::from_hex(COMPOSITE_KEY_PASSWORD).unwrap();
        let password = b"password";
        let salt = b"othersalt";
        let mut custom_data = HashMap::new();
        custom_data.insert("S".to_string(), salt.to_vec());
        custom_data.insert("V".to_string(), make_u32(0x13));
        custom_data.insert("M".to_string(), make_u64(65536));
        custom_data.insert("I".to_string(), make_u64(10));
        custom_data.insert("P".to_string(), make_u32(4));
        let transform_key = transform_argon2(&password[..], &custom_data);
        assert!(transform_key.is_ok());
    }

    #[test]
    fn test_argon2_kdf_alternate() {
        let password = b"asdf";
        let salt = b"7kAWcXSFs31RtR0g";
        let hash = "eff8bd51dae17d129c135de8097049362977529d81aa4f279190ee73b8a08810";
        let hash_raw = Vec::from_hex(hash).unwrap();
        let mut custom_data = HashMap::new();
        custom_data.insert("S".to_string(), salt.to_vec());
        custom_data.insert("V".to_string(), make_u32(0x13));
        custom_data.insert("M".to_string(), make_u64(24));
        custom_data.insert("I".to_string(), make_u64(20));
        custom_data.insert("P".to_string(), make_u32(3));
        let transform_key = transform_argon2(&password[..], &custom_data);
        assert!(transform_key.is_ok());
        let transform_key_raw = transform_key.unwrap();
        assert_eq!(transform_key_raw, hash_raw);
    }

    #[test]
    fn test_argon2_kdf_defaults() {
        assert!(false);
    }

    #[test]
    fn test_argon2_kdf_secret_and_associative() {
        assert!(false);
    }
}

fn make_u64(value: u64) -> Vec<u8> {
    let out = vec![0; 8];
    let mut cursor = Cursor::new(out);
    cursor.write_u64::<LittleEndian>(value).unwrap();
    cursor.into_inner()
}

fn unmake_u32(value: &[u8]) -> Option<u32> {
    if value.len() != 4 {
        return None
    }
    let mut cursor = Cursor::new(value);
    Some(cursor.read_u32::<LittleEndian>().unwrap())
}

fn unmake_u64(value: &[u8]) -> Option<u64> {
    if value.len() != 8 {
        return None
    }
    let mut cursor = Cursor::new(value);
    Some(cursor.read_u64::<LittleEndian>().unwrap())
}

fn unmake_u64_be(value: &[u8]) -> Option<u64> {
    if value.len() != 8 {
        return None
    }
    let mut cursor = Cursor::new(value);
    Some(cursor.read_u64::<BigEndian>().unwrap())
}

struct Key {
    user_password: Option<Vec<u8>>,
    keyfile: Option<Vec<u8>>,
    windows_credentials: Option<Vec<u8>>,
}

impl Key {
    fn new() -> Key {
        Key {
            user_password: None,
            keyfile: None,
            windows_credentials: None,
        }
    }

    fn set_user_password<T>(&mut self, user_password: T)
        where T : AsRef<[u8]> {
            let mut context = Context::new(&SHA256);
            context.update(user_password.as_ref());
            self.user_password = Some(context.finish().as_ref().to_owned());
    }

    /* TODO Use this function */
    fn _set_keyfile<T>(&mut self, keyfile: T)
        where T : AsRef<[u8]> {
            let mut context = Context::new(&SHA256);
            context.update(keyfile.as_ref());
            self.keyfile = Some(context.finish().as_ref().to_owned());
    }

    /* TODO Use this function */
    fn _set_windows_credentials<T>(&mut self, windows_credentials: T)
        where T : AsRef<[u8]> {
            let mut context = Context::new(&SHA256);
            context.update(windows_credentials.as_ref());
            self.windows_credentials = Some(context.finish().as_ref().to_owned());
    }

    fn composite_key(&self) -> Vec<u8> {
        let mut context = Context::new(&SHA256);

        if let Some(key) = &self.user_password {
            context.update(&key);
        }

        if let Some(key) = &self.keyfile {
            context.update(&key);
        }

        if let Some(key) = &self.windows_credentials {
            context.update(&key);
        }

        context.finish().as_ref().to_owned()
    }

    fn composite_key_kdb1(&self) -> Vec<u8> {
        if self.user_password == None {
            return self.keyfile.clone().unwrap();
        }

        if self.keyfile == None {
            return self.user_password.clone().unwrap();
        }

        let mut context = Context::new(&SHA256);
        context.update(&self.user_password.clone().unwrap());
        context.update(&self.keyfile.clone().unwrap());
        context.finish().as_ref().to_owned()
    }
}

fn transform_aes_kdf(composite_key: &[u8], custom_data: &HashMap<String, Vec<u8>>) -> io::Result<Vec<u8>> {
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

const KDF_PARAM_UUID         : &str = "$UUID"; // UUID, KDF used to derive master key
const KDF_PARAM_SALT         : &str = "S"; // Byte[], Generates 32 bytes, required
const KDF_PARAM_ROUNDS       : &str = "R"; // Byte[], Generates 32 bytes, required
const KDF_PARAM_PARALLELISM  : &str = "P"; // UInt32, Default, required
const KDF_PARAM_MEMORY       : &str = "M"; // UInt64, Default, required
const KDF_PARAM_ITERATIONS   : &str = "I"; // UInt64, Default, required
const KDF_PARAM_VERSION      : &str = "V"; // UInt32, Min/Max, Default Max, required
const _KDF_PARAM_SECRET_KEY   : &str = "K"; // Byte[]
const _KDF_PARAM_ASSOC_DATA   : &str = "A"; // Byte[]

/* TODO Use these defaults */
const _DEFAULT_ITERATIONS     : u64 = 2;
const _DEFAULT_MEMORY         : u64 = 1024 * 1024;
const _DEFAULT_PARALLELISM    : u32 = 2;

#[cfg(feature = "rust-argon2")]
fn transform_argon2_lib(composite_key: &[u8], salt: &[u8], version: u32, mem_cost: u32, time_cost: u32, lanes: u32) -> io::Result<Vec<u8>> {
    let version = match version {
        0x13 => Version::Version13,
        0x10 => Version::Version10,
        _ => { panic!("Misconfigured!"); },
    };
    let config = Config {
        variant: Variant::Argon2d,
        version,
        mem_cost,
        time_cost,
        lanes,
        thread_mode: ThreadMode::Parallel,
        secret: &[],
        ad: &[],
        hash_length: 32
    };
    let hash = argon2::hash_raw(composite_key, salt, &config).unwrap();
    println!("P: {:0x?}, S: {:0x?}, H: {:0x?}, C: {:#?}", composite_key, salt, hash, config);
    Ok(hash)
}

#[cfg(feature = "argonautica")]
fn transform_argon2_lib(composite_key: &[u8], salt: &[u8], version: u32, mem_cost: u32, time_cost: u32, lanes: u32) -> io::Result<Vec<u8>> {
    let version = match version {
        0x13 => Version::_0x13,
        0x10 => Version::_0x10,
        _ => { panic!("Misconfigured!"); },
    };
    let mut hasher = Hasher::default();
    hasher
        .configure_iterations(time_cost)
        .configure_lanes(lanes)
        .configure_memory_size(mem_cost)
        .configure_variant(Variant::Argon2d)
        .configure_version(version)
        .opt_out_of_secret_key(true);
    //println!("P: {:0x?}, S: {:0x?}, H: {:0x?}, C: {:#?}", composite_key, salt, b"", hasher);//hash, config);
    Ok(hasher
        .with_password(composite_key)
        .with_salt(salt)
        .hash_raw()
        .unwrap()
        .raw_hash_bytes()
        .to_owned())
}

#[cfg(any(feature = "rust-argon2", feature = "argonautica"))]
fn transform_argon2(composite_key: &[u8], custom_data: &HashMap<String, Vec<u8>>) -> io::Result<Vec<u8>> {
    let salt = match custom_data.get(KDF_PARAM_SALT) {
        Some(x) => x,
        None => {
            return Err(io::Error::new(io::ErrorKind::Other, "Argon2 salt missing"));
        },
    };
    let version = match custom_data.get(KDF_PARAM_VERSION) {
        Some(x) => {
            match unmake_u32(x) {
                Some(x) if x > 0x13 => {
                    println!("Version: {}", x);
                    return Err(io::Error::new(io::ErrorKind::Other, "Argon2 version too new"));
                },
                Some(x) if x == 0x13 => 0x13,
                Some(x) if x >= 0x10 => 0x10,
                Some(_) => {
                    return Err(io::Error::new(io::ErrorKind::Other, "Argon2 version too old"));
                },
                None => {
                    return Err(io::Error::new(io::ErrorKind::Other, "Invalid version"));
                },
            }
        },
        None => {
            return Err(io::Error::new(io::ErrorKind::Other, "Argon2 version missing"));
        },
    };
    let mem_cost = match custom_data.get(KDF_PARAM_MEMORY) {
        Some(x) => {
            match unmake_u64(x) {
                Some(x) => x/1024,
                None => {
                    return Err(io::Error::new(io::ErrorKind::Other, "Invalid memory parameter"));
                },
            }
        },
        None => {
            return Err(io::Error::new(io::ErrorKind::Other, "Argon2 memory parameter missing"));
        },
    };
    let time_cost = match custom_data.get(KDF_PARAM_ITERATIONS) {
        Some(x) => {
            match unmake_u64(x) {
                Some(x) => x,
                None => {
                    return Err(io::Error::new(io::ErrorKind::Other, "Invalid time parameter"));
                },
            }
        },
        None => {
            return Err(io::Error::new(io::ErrorKind::Other, "Argon2 time parameter missing"));
        },
    };
    let lanes = match custom_data.get(KDF_PARAM_PARALLELISM) {
        Some(x) => {
            match unmake_u32(x) {
                Some(x) => x,
                None => {
                    return Err(io::Error::new(io::ErrorKind::Other, "Invalid parallelism parameter"));
                },
            }
        },
        None => {
            return Err(io::Error::new(io::ErrorKind::Other, "Argon2 parallelism parameter missing"));
        },
    };
    let hash = transform_argon2_lib(composite_key, salt, version, mem_cost as u32, time_cost as u32, lanes).unwrap();
    Ok(hash)
}

#[cfg(not(any(feature = "rust-argon2", feature = "argonautica")))]
fn transform_argon2(_composite_key: &[u8], custom_data: &HashMap<String, Vec<u8>>) -> io::Result<Vec<u8>> {
    Err(io::Error::new(io::ErrorKind::Other, "Argon2 unimplemented"))
}

fn decode_string_kdb1(mut content: Vec<u8>) -> String {
    if content[content.len()-1] != 0 {
        panic!("Need null terminator");
    }
    content.truncate(content.len()-1);
    String::from_utf8(content).unwrap()
}

fn decode_datetime_kdb1(content: &[u8]) -> NaiveDateTime {
    let mut buf = vec![0, 0, 0];
    buf.extend(content);
    let mut raw = unmake_u64_be(&buf).unwrap();
    //println!("{:010x}: {:?}", raw, buf);
    let second = raw & 0x3f;
    raw >>= 6;
    let minute = raw & 0x3f;
    raw >>= 6;
    let hour = raw & 0x1f;
    raw >>= 5;
    let day = raw & 0x1f;
    raw >>= 5;
    let month = raw & 0x0f;
    raw >>= 4;
    let year = raw & 0xfff;
    NaiveDate::from_ymd(year as i32, month as u32, day as u32)
              .and_hms(hour as u32, minute as u32, second as u32)
}

const KDF_AES_KDBX3: &str = "c9d9f39a-628a-4460-bf74-0d08c18a4fea";
const KDF_AES_KDBX4: &str = "7c02bb82-79a7-4ac0-927d-114a00648238";
const KDF_ARGON2   : &str = "ef636ddf-8c29-444b-91f7-a9a403e30a0c";

fn main() -> io::Result<()> {
    env_logger::init();

    let mut stderr = io::stderr();

    println!("Hello, world!");

    let filename = match env::args().nth(1) {
        Some(f) => f,
        None => {
            let _ = writeln!(stderr, "Invalid database file\n");
            process::exit(1);
        }
    };

    let mut key = Key::new();
    let user_password = match env::var("KDBX_PASSWORD") {
        Ok(password) => password,
        Err(env::VarError::NotPresent) => read_password().unwrap(),
        Err(env::VarError::NotUnicode(_)) => {
            panic!("Invalid password");
        },
    };
    key.set_user_password(user_password);
    let composite_key = key.composite_key();

    let mut file = File::open(filename)?;
    let magic = file.read_u32::<LittleEndian>()?;
    let magic_type = file.read_u32::<LittleEndian>()?;

    if magic != 0x9AA2D903 {
        let _ = writeln!(stderr, "Invalid database file\n");
        process::exit(1);
    }

    let kdf_aes_kdbx3 = Uuid::parse_str(KDF_AES_KDBX3).unwrap();
    let kdf_aes_kdbx4 = Uuid::parse_str(KDF_AES_KDBX4).unwrap();
    let kdf_argon2    = Uuid::parse_str(KDF_ARGON2   ).unwrap();
    let mut custom_data = HashMap::<String, Vec<u8>>::new();

    match magic_type {
        0xB54BFB65 => {
            let flags = file.read_u32::<LittleEndian>()?;
            let version = file.read_u32::<LittleEndian>()?;
            let mut master_seed = vec![0; 16];
            file.read_exact(&mut master_seed)?;
            let mut encryption_iv = vec![0; 16];
            file.read_exact(&mut encryption_iv)?;
            let num_groups = file.read_u32::<LittleEndian>()?;
            let num_entries = file.read_u32::<LittleEndian>()?;
            let mut content_hash = vec![0; 32];
            file.read_exact(&mut content_hash)?;
            let mut transform_seed = vec![0; 32];
            file.read_exact(&mut transform_seed)?;
            let transform_round = file.read_u32::<LittleEndian>()?;
            println!("flags: {}, version: {}, groups: {}, entries: {}, round: {:?}", flags, version, num_groups, num_entries, transform_round);

            println!("AES");

            custom_data.insert(KDF_PARAM_SALT.to_string(), transform_seed);
            custom_data.insert(KDF_PARAM_ROUNDS.to_string(), make_u64(transform_round as u64));

            let transform_key = transform_aes_kdf(&key.composite_key_kdb1(), &custom_data)?;

            println!("Key OUT: {:0x?}", transform_key);

            println!("Calculating master key");
            let mut hmac_context = Context::new(&SHA512);

            let mut master_key = master_seed.to_owned();
            master_key.extend(transform_key);
            let mut context = Context::new(&SHA256);
            context.update(&master_key);
            hmac_context.update(&master_key);
            hmac_context.update(&[1u8]);
            master_key = context.finish().as_ref().to_owned();
            println!("Master OUT: {:0x?}", master_key);

            let mut ciphertext = vec![];
            file.read_to_end(&mut ciphertext)?;

            println!("MK: {}, IV: {}, CP: {}", master_key.len(), encryption_iv.len(), ciphertext.len());
            let data = decrypt(Cipher::aes_256_cbc(), &master_key, Some(encryption_iv.as_ref()), &ciphertext).unwrap();

            let mut context = Context::new(&SHA256);
            context.update(&data);
            let hash = context.finish().as_ref().to_owned();
            if hash != content_hash {
                println!("Failed to decode");
                process::exit(1);
            }

            let mut c = Cursor::new(data);
            println!("Groups:");
            for _ in 0..num_groups {
                loop {
                    let field_type = c.read_u16::<LittleEndian>()?;
                    let field_len = c.read_u32::<LittleEndian>()?;
                    let mut field_content = vec![0; field_len as usize];
                    c.read_exact(&mut field_content)?;
                    if field_type == 0xffff {
                        break;
                    }
                    //println!("TLV({}, {}): {:?}", field_type, field_len, field_content);
                    match field_type {
                        0x0000 => {
                            //readExtData(dataInput);
                        },
                        0x0001 => {
                            let mut c = Cursor::new(field_content);
                            let uuid = c.read_u32::<LittleEndian>()?;
                            println!("UUID: {}", uuid);
                        },
                        0x0002 => {
                            let name = decode_string_kdb1(field_content);
                            println!("Name: {}", name);
                        },
                        0x0003 => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            println!("Creation Time: {}", datetime.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x0004 => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            println!("Last Modification Time: {}", datetime.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x0005 => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            println!("Last Access Time: {}", datetime.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x0006 => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            println!("Expiry Time: {}", datetime.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x0007 => {
                            let mut c = Cursor::new(field_content);
                            let icon = c.read_u32::<LittleEndian>()?;
                            println!("Icon: {}", icon);
                        },
                        0x0008 => {
                            //int level = readShort(dataInput);
                            //group.setParent(computeParentGroup(lastGroup, level));
                            let mut c = Cursor::new(field_content);
                            let level = c.read_u16::<LittleEndian>()?;
                            println!("Level: {}", level);
                        },
                        0x0009 => {
                            let mut c = Cursor::new(field_content);
                            let flags = c.read_u32::<LittleEndian>()?;
                            println!("Flags: 0x{:08x}", flags);
                        },
                        _ => {
                            panic!("Unknown field");
                        },
                    };
                }
                println!("");
            }
            println!("Entries:");
            for _ in 0..num_entries {
                loop {
                    let field_type = c.read_u16::<LittleEndian>()?;
                    let field_len = c.read_u32::<LittleEndian>()?;
                    let mut field_content = vec![0; field_len as usize];
                    c.read_exact(&mut field_content)?;
                    if field_type == 0xffff {
                        break;
                    }
                    //println!("TLV({}, {}): {:?}", field_type, field_len, field_content);
                    match field_type {
                        0x0000 => {
                            //readExtData(dataInput);
                        },
                        0x0001 => {
                            let mut c = Cursor::new(field_content);
                            let uuid = c.read_u32::<LittleEndian>()?;
                            println!("UUID: {}", uuid);
                        },
                        0x0002 => {
                            let mut c = Cursor::new(field_content);
                            let group_id = c.read_u32::<LittleEndian>()?;
                            println!("Group: {}", group_id);
                        },
                        0x0003 => {
                            let mut c = Cursor::new(field_content);
                            let icon = c.read_u32::<LittleEndian>()?;
                            println!("Icon: {}", icon);
                        },
                        0x0004 => {
                            let name = decode_string_kdb1(field_content);
                            println!("Title: {}", name);
                        },
                        0x0005 => {
                            let name = decode_string_kdb1(field_content);
                            println!("Url: {}", name);
                        },
                        0x0006 => {
                            let name = decode_string_kdb1(field_content);
                            println!("Username: {}", name);
                        },
                        0x0007 => {
                            let name = decode_string_kdb1(field_content);
                            println!("Password: {}", name);
                        },
                        0x0008 => {
                            let name = decode_string_kdb1(field_content);
                            println!("Notes: {}", name);
                        },
                        0x0009 => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            println!("Creation Time: {}", datetime.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x000a => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            println!("Last Modification Time: {}", datetime.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x000b => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            println!("Last Access Time: {}", datetime.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x000c => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            println!("Expiry Time: {}", datetime.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x000d => {
                            let name = decode_string_kdb1(field_content);
                            println!("Binary Description: {}", name);
                        },
                        0x000e => {
                            println!("Binary Data: {:#?}", field_content);
                        },
                        _ => {
                            panic!("Unknown field");
                        },
                    };
                }
                println!("");
            }
            return Ok(());
        },
        0xB54BFB66 => {
            // XXX Untested
            let _ = writeln!(stderr, "KeePass 2.x Beta files not supported\n");
            process::exit(1);
        },
        0xB54BFB67 => {
            println!("Opening KeePass 2.x database");
        },
        _ => {
            // XXX Untested
            let _ = writeln!(stderr, "Unknown KeePass database format\n");
            process::exit(1);
        },
    };

    // Version field is defined as uint32_t, but it's broken up into
    // major and minor 16-bit components. Due to the nature of little
    // endian, this puts the minor part first.
    let minor_version = file.read_u16::<LittleEndian>()?;
    let major_version = file.read_u16::<LittleEndian>()?;
    match major_version {
        3 => {
            custom_data.insert(KDF_PARAM_UUID.to_string(), kdf_aes_kdbx3.as_bytes().to_vec());
        },
        4 => {
        },
        _ => {
            let _ = writeln!(stderr,
                     "Unsupported KeePass 2.x database version ({}.{})\n",
                     major_version, minor_version);
            process::exit(1);
        },
    };
    let mut tlvs = HashMap::new();
    loop {
        let tlv_type = file.read_u8()?;
        let tlv_len = if major_version == 4 {
            file.read_u32::<LittleEndian>()?
        } else {
            // XXX Untested
            file.read_u16::<LittleEndian>()? as u32
        };
        let mut tlv_data = vec![0; tlv_len as usize];
        file.read_exact(&mut tlv_data)?;
        debug!("TLV({}, {}): {:?}", tlv_type, tlv_len, tlv_data);
        match tlv_type {
            0 => { break; }
            5 => { custom_data.insert(KDF_PARAM_SALT.to_string(), tlv_data); },
            6 => { custom_data.insert(KDF_PARAM_ROUNDS.to_string(), tlv_data); },
            11 => {
                let kdf_parameters = &tlv_data;
                let mut c = Cursor::new(kdf_parameters);
                let variant_minor = c.read_u8()?;
                let variant_major = c.read_u8()?;
                if variant_major != 1 {
                    let _ = writeln!(stderr,
                             "Unsupported variant dictionary version ({}.{})\n",
                             variant_major, variant_minor);
                    process::exit(1);
                };

                loop {
                    let item_type = c.read_u8()?;
                    if item_type == 0 {
                        break;
                    }
                    let item_key_len = c.read_u32::<LittleEndian>()?;
                    let mut item_key = vec![0; item_key_len as usize];
                    c.read_exact(&mut item_key)?;
                    let item_key_str = String::from_utf8_lossy(&item_key).to_owned();
                    let item_value_len = c.read_u32::<LittleEndian>()?;
                    let mut item_value = vec![0; item_value_len as usize];
                    c.read_exact(&mut item_value)?;
                    debug!("K: {}, V: {:0x?}", item_key_str, item_value);
                    custom_data.insert(item_key_str.to_owned().to_string(), item_value);
                }
            },
            _ => { tlvs.insert(tlv_type, tlv_data); },
        }
    };

    //let src = &tlvs[&2u8];
    //let mut uuid = [0; 16];
    //let b = &src[..uuid.len()];
    //uuid.copy_from_slice(b);
    //let d = Builder::from_bytes(uuid).build();
    let cipher_id = Builder::from_slice(&tlvs[&2u8]).unwrap().build();
    println!("D: {:?}", cipher_id);
    if cipher_id != Uuid::parse_str("31c1f2e6-bf71-4350-be58-05216afc5aff").unwrap() {
        let _ = writeln!(stderr, "Unknown cipher\n");
        process::exit(1);
    }
    println!("AES");
    let mut c = Cursor::new(&tlvs[&3u8]);
    let compression_flags = c.read_u32::<LittleEndian>()?;
    match compression_flags {
        0 => {
            // XX Untested
            let _ = writeln!(stderr, "Unsupported no compressed file\n");
            process::exit(1);
        },
        1 => {
            println!("Gzip compression");
        },
        _ => {
            // XX Untested
            let _ = writeln!(stderr, "Unsupported compression method\n");
            process::exit(1);
        },
    };

    let master_seed = &tlvs[&4u8];
    let encryption_iv = &tlvs[&7u8];

    let mut header = vec![];
    if major_version == 4 {
        let mut context = Context::new(&SHA256);
        let pos = file.seek(SeekFrom::Current(0))?;
        file.seek(SeekFrom::Start(0))?;
        header = vec![0; (pos) as usize];
        file.read_exact(&mut header)?;
        file.seek(SeekFrom::Start(pos))?;
        context.update(&header);
        let digest = context.finish();
        let mut expected_hash = [0; 32];
        file.read_exact(&mut expected_hash)?;
        if digest.as_ref() != expected_hash {
            let _ = writeln!(stderr, "Possible header corruption\n");
            process::exit(1);
        }
    }

    let kdf_id = Builder::from_slice(&custom_data[KDF_PARAM_UUID]).unwrap().build();
    println!("KDF: {:?}", kdf_id);

    let transform_key = match kdf_id {
        x if x == kdf_aes_kdbx3 => {
            //panic!("KDBX 3 AES-KDF not supported!");
            transform_aes_kdf(&composite_key, &custom_data)?
        },
        x if x == kdf_aes_kdbx4 => {
            panic!("KDBX 4 AES-KDF not supported!");
        },
        x if x == kdf_argon2 => {
            transform_argon2(&composite_key, &custom_data)?
            //panic!("Argon2 KDF not supported!");
        },
        _ => {
            panic!("Unknown");
        },
    };

    println!("Key OUT: {:0x?}", transform_key);

    println!("Calculating master key");
    let mut hmac_context = Context::new(&SHA512);

    let mut master_key = master_seed.to_owned();
    master_key.extend(transform_key);
    let mut context = Context::new(&SHA256);
    context.update(&master_key);
    hmac_context.update(&master_key);
    hmac_context.update(&[1u8]);
    master_key = context.finish().as_ref().to_owned();
    let hmac_key_base = hmac_context.finish().as_ref().to_owned();
    println!("Master OUT: {:0x?}", master_key);
    println!("HMAC OUT: {:0x?}", hmac_key_base);

    let mut hmac_context = Context::new(&SHA512);
    hmac_context.update(&[0xff; 8]);
    hmac_context.update(&hmac_key_base);
    let hmac_key = hmac_context.finish().as_ref().to_owned();

    let mut hmac_tag = [0; 32];
    //println!("HMAC Tag: {:0x?}", hmac_tag);
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key);
    if major_version == 4 {
        file.read_exact(&mut hmac_tag)?;
        println!("Verifying HMAC");
        hmac::verify(&hmac_key, &header, &hmac_tag).unwrap();
        println!("Complete");
    }

    let mut ciphertext = vec![];
    for idx in 0.. {
        println!("Block {}", idx);
        if major_version == 4 {
            file.read_exact(&mut hmac_tag)?;
        } else {
            let mut ciphertext = vec![];
            file.read_to_end(&mut ciphertext)?;
            println!("CP: {:?}", ciphertext);
            let data = decrypt(Cipher::aes_256_cbc(), &master_key, Some(encryption_iv), &ciphertext).unwrap();
            println!("Data: {:?}", data);
            let mut c = Cursor::new(data);
            let mut start_stream = vec![0; 32];
            c.read_exact(&mut start_stream)?;
            assert_eq!(&start_stream, &tlvs[&9u8]);
            //let mut gz = GzDecoder::new(c);
            let block_id = c.read_u32::<LittleEndian>()?;
            assert_eq!(idx as u32, block_id);
            println!("ID: {}", block_id);
            let mut block_hash_expected = vec![0; 32];
            c.read_exact(&mut block_hash_expected)?;
            println!("Hash: {:?}", block_hash_expected);
            let block_size = c.read_u32::<LittleEndian>()?;
            println!("Size: {}", block_size);
            let mut block_data = vec![0; block_size as usize];
            c.read_exact(&mut block_data)?;
            println!("Read");
            let mut context = Context::new(&SHA256);
            context.update(&block_data);
            let block_hash = context.finish().as_ref().to_owned();
            assert_eq!(block_hash_expected, block_hash, "Failed hash");
            println!("Hash passed");
            let mut gz = GzDecoder::new(Cursor::new(block_data));
            let mut xml_file = File::create("data2.xml")?;
            let mut contents = String::new();
            gz.read_to_string(&mut contents)?;
            let _ = xml_file.write(&contents.as_bytes());
            return Ok(());
        }
        let block_size = file.read_u32::<LittleEndian>()?;
        if block_size == 0 {
            break;
        }
        let mut block = vec![0; block_size as usize];
        file.read_exact(&mut block)?;

        let mut hmac_context = Context::new(&SHA512);
        let mut buf = Cursor::new(Vec::new());
        buf.write_u64::<LittleEndian>(idx)?;
        hmac_context.update(buf.get_ref());
        hmac_context.update(&hmac_key_base);
        let hmac_key = hmac_context.finish().as_ref().to_owned();
        buf.write_u32::<LittleEndian>(block_size)?;
        buf.write(&block)?;
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key);
        println!("Verifying HMAC");
        hmac::verify(&hmac_key, buf.get_ref(), &hmac_tag).unwrap();
        println!("Complete");
        ciphertext.extend(block);
    };

    let data = decrypt(Cipher::aes_256_cbc(), &master_key, Some(encryption_iv), &ciphertext).unwrap();
    let mut gz = GzDecoder::new(Cursor::new(data));

    let mut tlvs = HashMap::new();
    loop {
        let tlv_type = gz.read_u8()?;
        let tlv_len = gz.read_u32::<LittleEndian>()?;
        let mut tlv_data = vec![0; tlv_len as usize];
        gz.read_exact(&mut tlv_data)?;
        if tlv_type == 0 {
            break;
        }
        debug!("TLV({}, {}): {:?}", tlv_type, tlv_len, tlv_data);
        tlvs.insert(tlv_type, tlv_data);
    };
    let mut xml_file = File::create("data.xml")?;
    //let mut buf = vec![];
    let mut contents = String::new();
    gz.read_to_string(&mut contents)?;
    //gz.read_to_end(&mut buf);
    let _ = xml_file.write(&contents.as_bytes());
    const KDBX4_TIME_OFFSET : i64 = 62135596800;
    let package = parser::parse(&contents).unwrap();
    let document = package.as_document();
    println!("Root element: {}", document.root().children()[0].element().unwrap().name().local_part());
    let database_name_node = evaluate_xpath(&document, "/KeePassFile/Meta/DatabaseName/text()").expect("Missing database name");
    println!("Database Name: {}", database_name_node.string());
    let database_name_changed_node = evaluate_xpath(&document, "/KeePassFile/Meta/DatabaseNameChanged/text()").expect("Missing database name changed");
    let timestamp = Cursor::new(decode(&database_name_changed_node.string()).expect("Valid base64")).read_i64::<LittleEndian>()? - KDBX4_TIME_OFFSET ;
    //let naive = NaiveDateTime::from_timestamp(timestamp, 0);
    //let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
    let datetime: DateTime<Local> = Local.timestamp(timestamp, 0);
    println!("Database Name Changed: {}", datetime.format("%Y-%m-%d %l:%M:%S %p %Z"));

    let xpath_username = Factory::new().build("String[Key/text() = 'UserName']/Value/text()").expect("Failed to compile XPath").expect("Empty XPath expression");
    let xpath_last_mod_time = Factory::new().build("Times/LastModificationTime/text()").expect("Failed to compile XPath").expect("Empty XPath expression");
    let xpath_password = Factory::new().build("String[Key/text() = 'Password']/Value[@Protected = 'True']/text()").expect("Failed to compile XPath").expect("Empty XPath expression");
    let xpath_context = XPathContext::new();
    let entry_nodes = evaluate_xpath(&document, "/KeePassFile/Root/Group/Entry").expect("Missing database entries");
    match entry_nodes {
        Value::Nodeset(nodes) => {
            for entry in nodes {
                //let n = evaluate_xpath(&document, "/KeePassFile/Root/Group/Entry/String[Key/text() = 'UserName']/Value/text()").expect("Missing entry username");
                let n = xpath_username.evaluate(&xpath_context, entry).expect("Missing entry username");
                let t = xpath_last_mod_time.evaluate(&xpath_context, entry).expect("Missing entry modification");
                let p = xpath_password.evaluate(&xpath_context, entry).expect("Missing entry password");
                println!("Name: {}", n.string());
                let timestamp = Cursor::new(decode(&t.string()).expect("Valid base64")).read_i64::<LittleEndian>()? - KDBX4_TIME_OFFSET;
                let datetime: DateTime<Local> = Local.timestamp(timestamp, 0);
                println!("Changed: {}", datetime.format("%Y-%m-%d %l:%M:%S %p %Z"));
                println!("P: {:?}, ('{}')", p, p.string());
                let mut p_ciphertext = decode(&p.string()).expect("Valid base64");
                let p_algo = unmake_u32(&tlvs[&0x01u8]).unwrap();
                assert_eq!(p_algo, 3);
                let p_key = &tlvs[&0x02u8];
                //let iv = Vec::from_hex("E830094B97205D2A").unwrap();
                println!("p_key: {}", p_key.len());
                let mut p_context = Context::new(&SHA512);
                p_context.update(p_key);
                let p2_key = p_context.finish().as_ref().to_owned();
                println!("p2_key: {}", p2_key.len());
                let key = GenericArray::from_slice(&p2_key[0..32]);
                let nonce = GenericArray::from_slice(&p2_key[32..32+12]);
                let mut cipher = ChaCha20::new(&key, &nonce);
                println!("Password Ciphertext: {:?}", p_ciphertext);
                cipher.apply_keystream(&mut p_ciphertext);
                //let data = decrypt(Cipher::chacha20(), &p2_key[0..32], Some(&p2_key[32..32+12]), &p_ciphertext).unwrap();
                println!("Password: {:?}", String::from_utf8(p_ciphertext).unwrap());
            }
        },
        _ => { panic!("XML corruption"); },
    };

    Ok(())
}
