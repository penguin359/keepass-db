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
extern crate argon2;

use std::io::Cursor;
use std::env;
use std::process;
use std::fs::File;
use std::io::{self, SeekFrom};
use std::io::prelude::*;
use std::collections::HashMap;

use hex::ToHex;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
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

use argon2::{Config, ThreadMode, Variant, Version};


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

    fn make_u64(value: u64) -> Vec<u8> {
        let out = vec![0; 8];
        let mut cursor = Cursor::new(out);
        cursor.write_u64::<LittleEndian>(value).unwrap();
        cursor.into_inner()
    }

    const ARGON2_HASH : &str = "4eb4d1f66ae3c88d85445fb49ae7c4a8fd51eeaa132c53cb8b37610f02569371";

    #[test]
    fn test_argon2_kdf() {
        //let data = Vec::from_hex(PASSWORD_SIMPLE).unwrap();
        //let mut key = Key::new();
        //key.set_user_password(data);
        //let composite_key = Vec::from_hex(COMPOSITE_KEY_PASSWORD).unwrap();
        let password = b"password";
        let salt = b"othersalt";
        let mut custom_data = HashMap::new();
        custom_data.insert("S".to_string(), salt.to_vec());
        custom_data.insert("V".to_string(), make_u32(13));
        custom_data.insert("M".to_string(), make_u64(65536));
        custom_data.insert("I".to_string(), make_u64(10));
        custom_data.insert("P".to_string(), make_u32(4));
        let transform_key = transform_argon2(&password[..], &custom_data);
        assert!(transform_key.is_ok());
    }
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

    fn set_keyfile<T>(&mut self, keyfile: T)
        where T : AsRef<[u8]> {
            let mut context = Context::new(&SHA256);
            context.update(keyfile.as_ref());
            self.keyfile = Some(context.finish().as_ref().to_owned());
    }

    fn set_windows_credentials<T>(&mut self, windows_credentials: T)
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
}

fn transform_aes_kdf(composite_key: &[u8], custom_data: &HashMap<String, Vec<u8>>) -> io::Result<Vec<u8>> {
    let transform_seed = &custom_data["S"];
    let mut c = Cursor::new(&custom_data["R"]);
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

const KDF_PARAM_SALT         : &str = "S"; // Byte[], Generates 32 bytes, required
const KDF_PARAM_PARALLELISM  : &str = "P"; // UInt32, Default, required
const KDF_PARAM_MEMORY       : &str = "M"; // UInt64, Default, required
const KDF_PARAM_ITERATIONS   : &str = "I"; // UInt64, Default, required
const KDF_PARAM_VERSION      : &str = "V"; // UInt32, Min/Max, Default Max, required
const KDF_PARAM_SECRET_KEY   : &str = "K"; // Byte[]
const KDF_PARAM_ASSOC_DATA   : &str = "A"; // Byte[]

const DEFAULT_ITERATIONS     : u64 = 2;
const DEFAULT_MEMORY         : u64 = 1024 * 1024;
const DEFAULT_PARALLELISM    : u32 = 2;

fn transform_argon2(composite_key: &[u8], custom_data: &HashMap<String, Vec<u8>>) -> io::Result<Vec<u8>> {
let password = b"password";
let salt = b"othersalt";
    let version = match custom_data.get(KDF_PARAM_VERSION) {
        Some(x) => {
            //match x.parse::<u32>() {
            match unmake_u32(x) {
                Some(x) => Version::Version13,
                None => { panic!(""); },
            }
        }
        /*
        Some(ref x) if x > 13 => {
            return Err(io::Result::new(io::ErrorKind::Other, "Argon2 version too new"));
        },
        Some(ref x) if x == 13 => Version::Version13,
        Some(ref x) if x >= 10 => Version::Version10,
        Some(ref x) => {
            return Err(io::Result::new(io::ErrorKind::Other, "Argon2 version too old"));
        },
        */
        None => {
            return Err(io::Error::new(io::ErrorKind::Other, "Argon2 version missing"));
        },
    };
    let config = Config {
        variant: Variant::Argon2d,
        version: version,
        mem_cost: 65536,
        time_cost: 10,
        lanes: 4,
        thread_mode: ThreadMode::Parallel,
        secret: &[],
        ad: &[],
        hash_length: 32
    };
let hash = argon2::hash_raw(password, salt, &config).unwrap();
    //Err(io::Error::new(io::ErrorKind::Other, "Argon2 unimplemented"))
    Ok(hash)
}

fn main() -> io::Result<()> {
    let mut stderr = io::stderr();

    println!("Hello, world!");

    let filename = match env::args().nth(1) {
        Some(f) => f,
        None => {
            writeln!(stderr, "Invalid database file\n")?;
            process::exit(1);
        }
    };

    let mut file = File::open(filename)?;
    let magic = file.read_u32::<LittleEndian>()?;
    let magic_type = file.read_u32::<LittleEndian>()?;

    if magic != 0x9AA2D903 {
        writeln!(stderr, "Invalid database file\n")?;
        process::exit(1);
    }
    match magic_type {
        0xB54BFB65 => {
            // XXX Untested
            writeln!(stderr, "KeePass 1.x files not supported\n")?;
            process::exit(1);
        },
        0xB54BFB66 => {
            // XXX Untested
            writeln!(stderr, "KeePass 2.x Beta files not supported\n")?;
            process::exit(1);
        },
        0xB54BFB67 => {
            println!("Opening KeePass 2.x database");
        },
        _ => {
            // XXX Untested
            writeln!(stderr, "Unknown KeePass database format\n")?;
            process::exit(1);
        },
    };

    // Version field is defined as uint32_t, but it's broken up into
    // major and minor 16-bit components. Due to the nature of little
    // endian, this puts the minor part first.
    let minor_version = file.read_u16::<LittleEndian>()?;
    let major_version = file.read_u16::<LittleEndian>()?;
    if major_version != 4 {
        writeln!(stderr,
                 "Unsupported KeePass 2.x database version ({}.{})\n",
                 major_version, minor_version)?;
        process::exit(1);
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
        if tlv_type == 0 {
            break;
        }
        println!("TLV({}, {}): {:?}", tlv_type, tlv_len, tlv_data);
        tlvs.insert(tlv_type, tlv_data);
    };

    //let src = &tlvs[&2u8];
    //let mut uuid = [0; 16];
    //let b = &src[..uuid.len()];
    //uuid.copy_from_slice(b);
    //let d = Builder::from_bytes(uuid).build();
    let cipher_id = Builder::from_slice(&tlvs[&2u8]).unwrap().build();
    println!("D: {:?}", cipher_id);
    if cipher_id != Uuid::parse_str("31c1f2e6-bf71-4350-be58-05216afc5aff").unwrap() {
        writeln!(stderr, "Unknown cipher\n")?;
        process::exit(1);
    }
    println!("AES");
    let mut c = Cursor::new(&tlvs[&3u8]);
    let compression_flags = c.read_u32::<LittleEndian>()?;
    match compression_flags {
        0 => {
            // XX Untested
            writeln!(stderr, "Unsupported no compressed file\n")?;
            process::exit(1);
        },
        1 => {
            println!("Gzip compression");
        },
        _ => {
            // XX Untested
            writeln!(stderr, "Unsupported compression method\n")?;
            process::exit(1);
        },
    };

    let master_seed = &tlvs[&4u8];
    let encryption_iv = &tlvs[&7u8];
    let kdf_parameters = &tlvs[&11u8];
    let mut c = Cursor::new(kdf_parameters);
    let variant_minor = c.read_u8()?;
    let variant_major = c.read_u8()?;
    if variant_major != 1 {
        writeln!(stderr,
                 "Unsupported variant dictionary version ({}.{})\n",
                 variant_major, variant_minor)?;
        process::exit(1);
    };

    let mut custom_data = HashMap::<String, Vec<u8>>::new();
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
        println!("K: {}, V: {:0x?}", item_key_str, item_value);
        custom_data.insert(item_key_str.to_owned().to_string(), item_value);
    }

    let mut context = Context::new(&SHA256);
    let header_start = 0;
    let pos = file.seek(SeekFrom::Current(0))?;
    file.seek(SeekFrom::Start(header_start))?;
    let mut header = vec![0; (pos-header_start) as usize];
    file.read_exact(&mut header)?;
    file.seek(SeekFrom::Start(pos))?;
    context.update(&header);
    let digest = context.finish();
    let mut expected_hash = [0; 32];
    file.read_exact(&mut expected_hash)?;
    if digest.as_ref() != expected_hash {
        writeln!(stderr, "Possible header corruption\n")?;
        process::exit(1);
    }

    let mut composite_key_intermediate = Vec::<u8>::new();

    let mut key = Key::new();
    let user_password = match env::var("KDBX_PASSWORD") {
        Ok(password) => password,
        Err(env::VarError::NotPresent) => read_password().unwrap(),
        Err(env::VarError::NotUnicode(_)) => {
            panic!("Invalid password");
        },
    };
    println!("User PW: {}", user_password.encode_hex::<String>());
    key.set_user_password(user_password);
    let composite_key = key.composite_key();
    println!("Composite Key: {}", composite_key.encode_hex::<String>());

    let kdf_id = Builder::from_slice(&custom_data["$UUID"]).unwrap().build();
    println!("KDF: {:?}", kdf_id);
    let kdf_aes_kdbx3 = Uuid::parse_str("c9d9f39a-628a-4460-bf74-0d08c18a4fea").unwrap();
    let kdf_aes_kdbx4 = Uuid::parse_str("7c02bb82-79a7-4ac0-927d-114a00648238").unwrap();
    let kdf_argon2    = Uuid::parse_str("ef636ddf-8c29-444b-91f7-a9a403e30a0c").unwrap();

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
    file.read_exact(&mut hmac_tag)?;
    //println!("HMAC Tag: {:0x?}", hmac_tag);
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key);
    println!("Verifying HMAC");
    hmac::verify(&hmac_key, &header, &hmac_tag).unwrap();

    println!("Complete");

    for idx in 0.. {
        println!("Block {}", idx);
        file.read_exact(&mut hmac_tag)?;
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

        let data = decrypt(Cipher::aes_256_cbc(), &master_key, Some(encryption_iv), &block).unwrap();
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
            println!("TLV({}, {}): {:?}", tlv_type, tlv_len, tlv_data);
            tlvs.insert(tlv_type, tlv_data);
        };
        //let mut xml_file = File::create("data.xml")?;
        //let mut buf = vec![];
        let mut contents = String::new();
        gz.read_to_string(&mut contents)?;
        //gz.read_to_end(&mut buf);
        //xml_file.write(&buf);
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
        let xpath_context = XPathContext::new();
        let entry_nodes = evaluate_xpath(&document, "/KeePassFile/Root/Group/Entry").expect("Missing database entries");
        match entry_nodes {
            Value::Nodeset(nodes) => {
                for entry in nodes {
                    //let n = evaluate_xpath(&document, "/KeePassFile/Root/Group/Entry/String[Key/text() = 'UserName']/Value/text()").expect("Missing entry username");
                    let n = xpath_username.evaluate(&xpath_context, entry).expect("Missing entry username");
                    let t = xpath_last_mod_time.evaluate(&xpath_context, entry).expect("Missing entry modification");
                    println!("Name: {}", n.string());
                    let timestamp = Cursor::new(decode(&t.string()).expect("Valid base64")).read_i64::<LittleEndian>()? - KDBX4_TIME_OFFSET ;
                    let datetime: DateTime<Local> = Local.timestamp(timestamp, 0);
                    println!("Changed: {}", datetime.format("%Y-%m-%d %l:%M:%S %p %Z"));
                }
            },
            _ => { panic!("XML corruption"); },
        };
    };

    Ok(())
}
