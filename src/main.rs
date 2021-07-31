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
extern crate rand;
extern crate clap;
extern crate xml;
extern crate serde;
extern crate serde_xml_rs;
extern crate yaserde;

//#[macro_use]
//extern crate serde_derive;

#[macro_use]
extern crate yaserde_derive;

use std::io::Cursor;
use std::env;
use std::process;
use std::fs::File;
use std::io::{self, SeekFrom};
use std::io::prelude::*;
use std::collections::HashMap;
//use std::cell::RefCell;
//use std::rc::Rc;

//use hex::ToHex;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use base64::{decode, encode};
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

use rand::Rng;
use clap::{Arg, App};
use xml::reader::{EventReader, ParserConfig, XmlEvent};
use xml::attribute::{OwnedAttribute};
use xml::name::{OwnedName};
use yaserde::{YaDeserialize, YaSerialize};

#[cfg(test)]
mod tests;

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
    fn set_keyfile<T>(&mut self, keyfile: T)
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


fn consume_element<R: Read>(reader: &mut EventReader<R>, name: OwnedName, _attributes: Vec<OwnedAttribute>) -> Result<Option<String>, String> {
    let mut elements = vec![];
    println!("A tag: {}", &name);
    elements.push(name);

    let mut string = None;

    let mut event = reader.next().map_err(|_|"Failed to retrieve next XML event")?;
    loop {
        match event {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document, start of document".to_string());
            },
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document, end of document".to_string());
            },
            XmlEvent::StartElement { name, .. } => {
                elements.push(name);
            },
            XmlEvent::Characters(k) => {
                string = Some(k);
            },
            XmlEvent::EndElement { name, .. } => {
                let start_tag = elements.pop().expect("Can't consume a bare end element");
                if start_tag != name {
                    return Err(format!("Start tag <{}> mismatches end tag </{}>", start_tag, name));
                }
            },
            _ => {
                // Consume any PI, text, comment, or cdata node
                //return Ok(());
            },
        };
        if elements.len() == 0 {
            return Ok(string);
        }
        event = reader.next().map_err(|_|"Failed to retrieve next XML event")?;
    }
}

pub enum ElementEvent {
    StartElement {
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
    },
    EndElement {
        name: OwnedName,
    },
}

fn find_next_element<R: Read>(reader: &mut EventReader<R>) -> Result<ElementEvent, String> {
    loop {
        match reader.next().map_err(|_|"Failed to retrieve next XML event")? {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::StartElement { name, attributes, .. } => {
                return Ok(ElementEvent::StartElement {
                    name,
                    attributes,
                });
            },
            XmlEvent::Characters(_) => {},
            XmlEvent::CData(_) => {},
            XmlEvent::Whitespace(_) => {},
            XmlEvent::ProcessingInstruction { .. } => {},
            XmlEvent::EndElement { name, .. } => {
                return Ok(ElementEvent::EndElement {
                    name,
                });
            },
            _ => {
                // Consume any PI, text, comment, or cdata node
                //return Ok(());
            },
        };
    }
}

fn decode_optional_string<R: Read>(reader: &mut EventReader<R>, name: OwnedName, _attributes: Vec<OwnedAttribute>) -> Result<Option<String>, String> {
    let mut elements = vec![];
    println!("A tag: {}", &name);
    elements.push(name);

    let mut string = String::new();

    let mut event = reader.next().map_err(|_|"Failed to retrieve next XML event")?;
    loop {
        match event {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::StartElement { name, .. } => {
                elements.push(name);
            },
            XmlEvent::Characters(k) => {
                string.push_str(&k);
            },
            XmlEvent::Whitespace(k) => {
                string.push_str(&k);
            },
            XmlEvent::CData(k) => {
                string.push_str(&k);
            },
            XmlEvent::EndElement { name, .. } => {
                let start_tag = elements.pop().expect("Can't consume a bare end element");
                if start_tag != name {
                    return Err(format!("Start tag <{}> mismatches end tag </{}>", start_tag, name));
                }
            },
            _ => {
                // Consume any PI, text, comment, or cdata node
                //return Ok(());
            },
        };
        if elements.len() == 0 {
            if string.len() == 0 {
                return Ok(None);
            } else {
                return Ok(Some(string));
        }
    }
        event = reader.next().map_err(|_|"")?;
    }
}

fn decode_string<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<String, String> {
    decode_optional_string(reader, name, attributes).map(|x| x.unwrap_or_else(|| "".into()))
}

fn decode_optional_bool<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Option<bool>, String> {
    decode_optional_string(reader, name, attributes).map(|x| x.map(|y| y.eq_ignore_ascii_case("true")))
}

fn decode_bool<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<bool, String> {
    decode_optional_bool(reader, name, attributes).map(|x| x.unwrap_or(false))
}

fn decode_optional_i64<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Option<i64>, String> {
    decode_optional_string(reader, name, attributes).map(|x| x.map(|y| y.parse().unwrap_or(0)))
}

fn decode_i64<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<i64, String> {
    decode_optional_i64(reader, name, attributes).map(|x| x.unwrap_or(0))
}

const KDBX4_TIME_OFFSET : i64 = 62135596800;
fn decode_optional_datetime<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Option<DateTime<Local>>, String> {
    decode_optional_string(reader, name, attributes).map(|x| x.map(|y| Local.timestamp(Cursor::new(decode(&y).expect("Valid base64")).read_i64::<LittleEndian>().unwrap() - KDBX4_TIME_OFFSET, 0)))
}

//fn decode_i64<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<DateTime<Local>, String> {
    //decode_optional_i64(reader, name, attributes).map(|x| x.unwrap_or(0))
//}

fn decode_optional_uuid<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Option<Uuid>, String> {
    decode_optional_string(reader, name, attributes).map(|x| x.map(|y| Uuid::from_slice(&decode(&y).expect("Valid base64")).unwrap()))
}

fn decode_item<R: Read>(reader: &mut EventReader<R>, _name: OwnedName, _attributes: Vec<OwnedAttribute>) -> Result<(String, String), String> {
    let mut key = String::new();
    let mut value = String::new();

    loop {
        match find_next_element(reader)? {
            ElementEvent::StartElement { name, .. } if name.local_name == "Key" => {
                key = decode_string(reader, name, vec![])?;
            },
            ElementEvent::StartElement { name, .. } if name.local_name == "Value" => {
                value = decode_string(reader, name, vec![])?;
            },
            ElementEvent::StartElement { name, .. } => {
                consume_element(reader, name, vec![])?;
            },
            ElementEvent::EndElement { name, .. } if name.local_name == "Item" => {
                return Ok((key, value));
            },
            ElementEvent::EndElement { .. } => {
                return Err("Wrong ending".to_string());
            },
        }
    }
}

fn decode_custom_data<R: Read>(reader: &mut EventReader<R>, pname: OwnedName, _attributes: Vec<OwnedAttribute>) -> Result<HashMap<String, String>, String> {
    //let mut elements = vec![];
    //elements.push(name);

    let mut data = HashMap::new();

    loop {
        match find_next_element(reader)? {
            ElementEvent::StartElement { name, .. } if name.local_name == "Item" => {
                let (key, value) = decode_item(reader, name, vec![])?;
                //data[key] = value;
                data.insert(key, value);
            },
            ElementEvent::StartElement { name, .. } => {
                consume_element(reader, name, vec![])?;
            },
            ElementEvent::EndElement { name, .. } if name == pname => {
                return Ok(data);
            },
            ElementEvent::EndElement { .. } => {
                return Err("Wrong ending".to_string());
            },
        }
    }
}

#[derive(Debug, Default)]
struct MemoryProtection {
    protect_title: bool,
    protect_user_name: bool,
    protect_password: bool,
    protect_url: bool,
    protect_notes: bool,
}

#[derive(Debug, Default)]
struct Meta {
    generator: String,
    database_name: String,
    database_name_changed: Option<DateTime<Local>>,
    database_description: String,
    database_description_changed: Option<DateTime<Local>>,
    default_user_name: String,
    default_user_name_changed: Option<DateTime<Local>>,
    maintenance_history_days: u32,
    color: String,
    master_key_changed: Option<DateTime<Local>>,
    master_key_change_rec: i64,
    master_key_change_force: i64,
    memory_protection: MemoryProtection,
    custom_icons: String,
    recycle_bin_enabled: bool,
    recycle_bin_uuid: Option<Uuid>,
    recycle_bin_changed: String,
    entry_templates_group: String,
    entry_templates_group_changed: String,
    last_selected_group: String,
    last_top_visible_group: String,
    history_max_items: String,
    history_max_size: String,
    settings_changed: Option<DateTime<Local>>,
    custom_data: HashMap<String, String>,
}

struct Group {
    _uuid: String,
    _name: String,
    _notes: String,
    _icon_id: u32,
    //times: Times,
    _is_expanded: String,
    //<DefaultAutoTypeSequence/>
    _enable_auto_type: String,
    _enable_searching: String,
    _last_top_visible_entry: String,
    //custom_data: CustomData,
    _group: Vec<Group>,
    _entry: Vec<Entry>,
}

#[derive(Debug, Default, PartialEq)]
struct Entry {
    _uuid: String,
    _icon_id: u32,
    // times: Times,
    // custom_data: CustomData,
}

#[derive(Default)]
struct KeePassFile {
    meta: Meta,
    _root: Vec<Group>,
}

fn decode_memory_protection<R: Read>(reader: &mut EventReader<R>, name: OwnedName, _attributes: Vec<OwnedAttribute>) -> Result<MemoryProtection, String> {
    let mut elements = vec![name];
    //elements.push(name);

    let mut protect_title = false;
    let mut protect_user_name = false;
    let mut protect_password = false;
    let mut protect_url = false;
    let mut protect_notes = false;
    while elements.len() > 0 {
        let event = reader.next().map_err(|_|"")?;
        println!("Decode meta...");
        match event {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "ProtectTitle" => {
                protect_title = decode_bool(reader, name, attributes)?;
                println!("ProtectTitle: {:?}", protect_title);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "ProtectUserName" => {
                protect_user_name = decode_bool(reader, name, attributes)?;
                println!("ProtectUserName: {:?}", protect_user_name);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "ProtectPassword" => {
                protect_password = decode_bool(reader, name, attributes)?;
                println!("ProtectPassword: {:?}", protect_password);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "ProtectURL" => {
                protect_url = decode_bool(reader, name, attributes)?;
                println!("ProtectURL: {:?}", protect_url);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "ProtectNotes" => {
                protect_notes = decode_bool(reader, name, attributes)?;
                println!("ProtectNotes: {:?}", protect_notes);
            },
            XmlEvent::StartElement { name, .. } => {
                elements.push(name);
            },
            XmlEvent::EndElement { name, .. } => {
                let start_tag = elements.pop().expect("Can't consume a bare end element");
                if start_tag != name {
                    return Err(format!("Start tag <{}> mismatches end tag </{}>", start_tag, name));
                }
            },
            _ => {
                // Consume any PI, text, comment, or cdata node
                //return Ok(());
            },
        };
    }
    Ok(MemoryProtection {
        protect_title,
        protect_user_name,
        protect_password,
        protect_url,
        protect_notes,
    })
}

fn decode_meta<R: Read>(reader: &mut EventReader<R>) -> Result<Meta, String> {
    //let mut elements: Vec<::xml::name::OwnedName> = vec![];
    //elements.push("Foo".into());
    let mut elements = vec![];
    elements.push(::xml::name::OwnedName::local("Meta"));
    //let mut elements: Vec<::xml::name::OwnedName> = vec![];
    //elements.push(::xml::name::Name::from("Foo").to_owned());
    //elements.push(::xml::name::Name::from("Foo").into());
    //let mut elements = vec![];
    //elements.push(::xml::name::OwnedName::from_str("Foo").unwrap());


    let mut generator = String::new();
    let mut database_name = String::new();
    let mut database_name_changed = None;
    let mut database_description = String::new();
    let database_description_changed = None;
    let mut default_user_name = String::new();
    let default_user_name_changed = None;
    let mut maintenance_history_days = 0;
    let color = String::new();
    let master_key_changed = None;
    let mut master_key_change_rec = 0;
    let mut master_key_change_force = 0;
    let mut memory_protection = MemoryProtection::default();
    let custom_icons = String::new();
    let mut recycle_bin_enabled = false;
    let mut recycle_bin_uuid = None;
    let recycle_bin_changed = String::new();
    let entry_templates_group = String::new();
    let entry_templates_group_changed = String::new();
    let last_selected_group = String::new();
    let last_top_visible_group = String::new();
    let history_max_items = String::new();
    let history_max_size = String::new();
    let settings_changed = None;
    let mut custom_data = HashMap::new();
    while elements.len() > 0 {
        let event = reader.next().map_err(|_|"")?;
        println!("Decode meta...");
        match event {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "Generator" => {
                generator = decode_string(reader, name, attributes)?;
                println!("Generator: {:?}", generator);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "DatabaseName" => {
                database_name = decode_string(reader, name, attributes)?;
                println!("DatabaseName: {:?}", database_name);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "DatabaseNameChanged" => {
                database_name_changed = decode_optional_datetime(reader, name, attributes)?;
                println!("DatabaseNameChanged: {:?}", database_name_changed);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "DatabaseDescription" => {
                database_description = decode_string(reader, name, attributes)?;
                println!("DatabaseDescription: {:?}", database_description);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "DefaultUserName" => {
                default_user_name = decode_string(reader, name, attributes)?;
                println!("DefaultUserName: {:?}", default_user_name);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "MaintenanceHistoryDays" => {
                maintenance_history_days = decode_i64(reader, name, attributes)? as u32;
                println!("MaintenanceHistoryDays: {:?}", maintenance_history_days);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "MasterKeyChangeRec" => {
                master_key_change_rec = decode_i64(reader, name, attributes)?;
                println!("MasterKeyChangeRec: {:?}", master_key_change_rec);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "MasterKeyChangeForce" => {
                master_key_change_force = decode_i64(reader, name, attributes)?;
                println!("MasterKeyChangeForce: {:?}", master_key_change_force);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "MemoryProtection" => {
                memory_protection = decode_memory_protection(reader, name, attributes)?;
                println!("MemoryProtection: {:?}", memory_protection);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "RecycleBinEnabled" => {
                recycle_bin_enabled = decode_bool(reader, name, attributes)?;
                println!("RecycleBinEnabled: {:?}", recycle_bin_enabled);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "RecycleBinUUID" => {
                recycle_bin_uuid = decode_optional_uuid(reader, name, attributes)?;
                println!("RecycleBinUUID: {:?}", recycle_bin_uuid);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "CustomData" => {
                custom_data = decode_custom_data(reader, name, attributes)?;
                println!("CustomData: {:?}", custom_data);
            },
            /*
                #[yaserde(rename = "DatabaseNameChanged")]
                database_name_changed: String,
                #[yaserde(rename = "DatabaseDescription")]
                database_description: String,
                #[yaserde(rename = "DatabaseDescriptionChanged")]
                database_description_changed: String,
                #[yaserde(rename = "DefaultUserName")]
                default_user_name: String,
                #[yaserde(rename = "DefaultUserNameChanged")]
                default_user_name_changed: String,
                #[yaserde(rename = "MaintenanceHistoryDays")]
                maintenance_history_days: String,
                #[yaserde(rename = "Color")]
                color: String,
                #[yaserde(rename = "MasterKeyChanged")]
                master_key_changed: String,
                #[yaserde(rename = "MasterKeyChangeRec")]
                master_key_change_rec: String,
                #[yaserde(rename = "MasterKeyChangeForce")]
                master_key_change_force: String,
                #[yaserde(rename = "MemoryProtection")]
                memory_protection: MemoryProtection,
                #[yaserde(rename = "CustomIcons")]
                custom_icons: String,
                #[yaserde(rename = "RecycleBinEnabled")]
                recycle_bin_enabled: String,
                //#[serde(rename = "RecycleBinUUID")]
                #[yaserde(rename = "RecycleBinUUID")]
                recycle_bin_uuid: Option<String>,
                #[yaserde(rename = "RecycleBinChanged")]
                recycle_bin_changed: String,
                #[yaserde(rename = "EntryTemplatesGroup")]
                entry_templates_group: String,
                #[yaserde(rename = "EntryTemplatesGroupChanged")]
                entry_templates_group_changed: String,
                #[yaserde(rename = "LastSelectedGroup")]
                last_selected_group: String,
                #[yaserde(rename = "LastTopVisibleGroup")]
                last_top_visible_group: String,
                #[yaserde(rename = "HistoryMaxItems")]
                history_max_items: String,
                #[yaserde(rename = "HistoryMaxSize")]
                history_max_size: String,
                #[yaserde(rename = "SettingsChanged")]
                settings_changed: KdbDate,
                #[yaserde(rename = "CustomData")]
                custom_data: CustomData,
            */
            XmlEvent::StartElement { name, .. } => {
                elements.push(name);
            },
            XmlEvent::EndElement { name, .. } => {
                let start_tag = elements.pop().expect("Can't consume a bare end element");
                if start_tag != name {
                    return Err(format!("Start tag <{}> mismatches end tag </{}>", start_tag, name));
                }
            },
            _ => {
                // Consume any PI, text, comment, or cdata node
                //return Ok(());
            },
        };
    }
    Ok(Meta {
        generator,
        database_name,
        database_name_changed,
        database_description,
        database_description_changed,
        default_user_name,
        default_user_name_changed,
        maintenance_history_days,
        color,
        master_key_changed,
        master_key_change_rec,
        master_key_change_force,
        memory_protection,
        custom_icons,
        recycle_bin_enabled,
        recycle_bin_uuid,
        recycle_bin_changed,
        entry_templates_group,
        entry_templates_group_changed,
        last_selected_group,
        last_top_visible_group,
        history_max_items,
        history_max_size,
        settings_changed,
        custom_data,
    })
}

//fn consume_element<R: Read>(reader: &mut yaserde::de::Deserializer<R>, mut event: XmlEvent) -> Result<(), String> {
fn decode_document<R: Read>(mut reader: &mut EventReader<R>) -> Result<KeePassFile, String> {
    //let mut elements: Vec<::xml::name::OwnedName> = vec![];
    //elements.push("Foo".into());
    let mut elements = vec![];
    elements.push(::xml::name::OwnedName::local("KeePassFile"));
    //let mut elements: Vec<::xml::name::OwnedName> = vec![];
    //elements.push(::xml::name::Name::from("Foo").to_owned());
    //elements.push(::xml::name::Name::from("Foo").into());
    //let mut elements = vec![];
    //elements.push(::xml::name::OwnedName::from_str("Foo").unwrap());
    let mut meta = Meta::default();

    let mut event = reader.next().map_err(|_|"")?;
    loop {
        println!("Decode document...");
        match event {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::StartElement { name, .. } if name.local_name == "Meta" => {
                meta = decode_meta(&mut reader)?;
                println!("Meta: {:?}", meta);
            },
            XmlEvent::StartElement { name, .. } => {
                println!("Document Tag: {}", name);
                elements.push(name);
            },
            XmlEvent::EndElement { name, .. } => {
                let start_tag = elements.pop().expect("Can't consume a bare end element");
                if start_tag != name {
                    return Err(format!("Start tag <{}> mismatches end tag </{}>", start_tag, name));
                }
            },
            _ => {
                // Consume any PI, text, comment, or cdata node
                //return Ok(());
            },
        };
        if elements.len() == 0 {
            return Ok(KeePassFile { meta, ..KeePassFile::default() });
        }
        event = reader.next().map_err(|_|"")?;
    }
}

fn main() -> io::Result<()> {
    env_logger::init();

    let mut stderr = io::stderr();

    println!("Hello, world!");

    let options = App::new("KDBX Dump")
        .version("0.1.0")
        .author("Loren M. Lang <lorenl@north-winds.org>")
        .about("Dumping KDBX Password files")
        .arg(Arg::with_name("key")
            .short("k")
            .long("key-file")
            .takes_value(true)
            .help("Key file for unlocking database"))
        .arg(Arg::with_name("file")
            .help("Password database")
            .required(true)
            .index(1))
        .get_matches();

    let filename = options.value_of("file").expect("missing filename");

    let mut key = Key::new();
    let user_password = match env::var("KDBX_PASSWORD") {
        Ok(password) => password,
        Err(env::VarError::NotPresent) => read_password().unwrap(),
        Err(env::VarError::NotUnicode(_)) => {
            panic!("Invalid password");
        },
    };
    key.set_user_password(user_password);

    if let Some(filename) = options.value_of("key") {
        let mut contents = vec![];
        File::open(filename)?.read_to_end(&mut contents)?;
        key.set_keyfile(contents);
    }

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

            //let mut uuid_map = HashMap::new();
            //let mut items = Vec::new();
            let mut rng = rand::thread_rng();
            struct KdbGroup {//<'a> {
                uuid: u32,
                parent: u32,
                name: String,
                creation_time: DateTime<Local>,
                modification_time: DateTime<Local>,
                access_time: DateTime<Local>,
                expiry_time: DateTime<Local>,
                icon: u32,
                flags: u32,
                //groups: Vec<&'a KdbGroup>,
                groups: Vec<u32>,
                entries: Vec<Uuid>,
            }

            struct KdbEntry {
                uuid: Uuid,
                parent: u32,
                icon: u32,
                title: String,
                url: String,
                username: String,
                password: String,
                notes: String,
                creation_time: DateTime<Local>,
                modification_time: DateTime<Local>,
                access_time: DateTime<Local>,
                expiry_time: DateTime<Local>,
                binary_description: String,
                binary_data: Vec<u8>,
            }

            let now = Local::now();
            let root_group_uuid = rng.gen();
            let root_group = KdbGroup {
                uuid: root_group_uuid,
                parent: 0,
                name: "Root".to_string(),
                creation_time: now,
                modification_time: now,
                access_time: now,
                expiry_time: now,
                icon: 1,
                flags: 0,
                groups: vec![],
                entries: vec![],
            };

            let mut all_groups = HashMap::new();
            let mut all_entries = HashMap::new();
            let mut groups_level = HashMap::new();
            all_groups.insert(root_group.uuid, root_group);
            groups_level.insert(0u16, root_group_uuid);

            let mut c = Cursor::new(data);
            println!("Groups:");
            for _ in 0..num_groups {
                let mut group = KdbGroup {
                    uuid: rng.gen(),
                    parent: root_group_uuid,
                    name: "".to_string(),
                    creation_time: now,
                    modification_time: now,
                    access_time: now,
                    expiry_time: now,
                    icon: 1,
                    flags: 0,
                    groups: vec![],
                    entries: vec![],
                };
                let mut level = 0;
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
                            assert!(false);
                        },
                        0x0001 => {
                            let mut c = Cursor::new(field_content);
                            let uuid = c.read_u32::<LittleEndian>()?;
                            group.uuid = uuid;
                            assert_eq!(c.position(), field_len as u64);
                            println!("UUID: {}", uuid);
                        },
                        0x0002 => {
                            let name = decode_string_kdb1(field_content);
                            group.name = name;
                            println!("Name: {}", group.name);
                        },
                        0x0003 => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            group.creation_time = datetime;
                            println!("Creation Time: {}", group.creation_time.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x0004 => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            group.modification_time = datetime;
                            println!("Last Modification Time: {}", group.modification_time.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x0005 => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            group.access_time = datetime;
                            println!("Last Access Time: {}", group.access_time.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x0006 => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            group.expiry_time = datetime;
                            println!("Expiry Time: {}", group.expiry_time.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x0007 => {
                            let mut c = Cursor::new(field_content);
                            let icon = c.read_u32::<LittleEndian>()?;
                            group.icon = icon;
                            assert_eq!(c.position(), field_len as u64);
                            println!("Icon: {}", icon);
                        },
                        0x0008 => {
                            //int level = readShort(dataInput);
                            //group.setParent(computeParentGroup(lastGroup, level));
                            let mut c = Cursor::new(field_content);
                            level = c.read_u16::<LittleEndian>()?;
                            assert_eq!(c.position(), field_len as u64);
                            println!("Level: {}", level);
                        },
                        0x0009 => {
                            let mut c = Cursor::new(field_content);
                            let flags = c.read_u32::<LittleEndian>()?;
                            group.flags = flags;
                            assert_eq!(c.position(), field_len as u64);
                            println!("Flags: 0x{:08x}", flags);
                        },
                        _ => {
                            panic!("Unknown field");
                        },
                    };
                }
                println!("");
                //root_group.groups.push(group.uuid);
                group.parent = *groups_level.get(&level).unwrap_or(&root_group_uuid);
                all_groups.get_mut(&group.parent).unwrap().groups.push(group.uuid);
                groups_level.insert(level, group.uuid);
                all_groups.insert(group.uuid, group);
                //groups_level.get_mut(&2).unwrap().groups.push(group.uuid);
                //let g = Rc::new(RefCell::new(group));
                //items.push(Rc::clone(&g));
                //let u = g.borrow().uuid;
                //uuid_map.insert(u, g);
            }
            println!("Entries:");
            for _ in 0..num_entries {
                let mut entry = KdbEntry {
                    uuid: Uuid::default(),
                    parent: 0,
                    icon: 0,
                    title: "".to_string(),
                    url: "".to_string(),
                    username: "".to_string(),
                    password: "".to_string(),
                    notes: "".to_string(),
                    creation_time: now,
                    modification_time: now,
                    access_time: now,
                    expiry_time: now,
                    binary_description: "".to_string(),
                    binary_data: vec![],
                };
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
                            assert!(false);
                        },
                        0x0001 => {
                            //let mut c = Cursor::new(field_content);
                            //let uuid = c.read_u32::<LittleEndian>()?;
                            //assert_eq!(c.position(), field_len as u64);
                            let uuid = Uuid::from_slice(&field_content).unwrap();
                            entry.uuid = uuid;
                            println!("UUID: {}", entry.uuid);
                        },
                        0x0002 => {
                            let mut c = Cursor::new(field_content);
                            let group_id = c.read_u32::<LittleEndian>()?;
                            entry.parent = group_id;
                            assert_eq!(c.position(), field_len as u64);
                            println!("Group: {}", entry.parent);
                        },
                        0x0003 => {
                            let mut c = Cursor::new(field_content);
                            let icon = c.read_u32::<LittleEndian>()?;
                            entry.icon = icon;
                            assert_eq!(c.position(), field_len as u64);
                            println!("Icon: {}", entry.icon);
                        },
                        0x0004 => {
                            let name = decode_string_kdb1(field_content);
                            entry.title = name;
                            println!("Title: {}", entry.title);
                        },
                        0x0005 => {
                            let name = decode_string_kdb1(field_content);
                            entry.url = name;
                            println!("Url: {}", entry.url);
                        },
                        0x0006 => {
                            let name = decode_string_kdb1(field_content);
                            entry.username = name;
                            println!("Username: {}", entry.username);
                        },
                        0x0007 => {
                            let name = decode_string_kdb1(field_content);
                            entry.password = name;
                            println!("Password: {}", entry.password);
                        },
                        0x0008 => {
                            let name = decode_string_kdb1(field_content);
                            entry.notes = name;
                            println!("Notes: {}", entry.notes);
                        },
                        0x0009 => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            entry.creation_time = datetime;
                            println!("Creation Time: {}", entry.creation_time.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x000a => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            entry.modification_time = datetime;
                            println!("Last Modification Time: {}", entry.modification_time.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x000b => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            entry.access_time = datetime;
                            println!("Last Access Time: {}", entry.access_time.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x000c => {
                            let date = decode_datetime_kdb1(&field_content);
                            let datetime = Local.from_utc_datetime(&date);
                            entry.expiry_time = datetime;
                            println!("Expiry Time: {}", entry.expiry_time.format("%Y-%m-%d %l:%M:%S %p %Z"));
                        },
                        0x000d => {
                            let name = decode_string_kdb1(field_content);
                            entry.binary_description = name;
                            println!("Binary Description: {}", entry.binary_description);
                        },
                        0x000e => {
                            entry.binary_data = field_content;
                            println!("Binary Data: {:#?}", entry.binary_data);
                        },
                        _ => {
                            panic!("Unknown field");
                        },
                    };
                }
                println!("");
                //let parent_group = all_groups.get_mut(&entry.parent).unwrap_or_else(|| all_groups.get_mut(&root_group_uuid).unwrap());
                let parent_group = match all_groups.get_mut(&entry.parent) {
                    Some(group) => group,
                    None => all_groups.get_mut(&root_group_uuid).unwrap(),
                };
                parent_group.entries.push(entry.uuid);
                entry.parent = parent_group.uuid;
                all_entries.insert(entry.uuid, entry);
            }

            struct KdbDatabase {
                groups: HashMap<u32, KdbGroup>,
                entries: HashMap<Uuid, KdbEntry>,
            }

            let database = KdbDatabase {
                groups: all_groups,
                entries: all_entries,
            };

            fn dump_group(database: &KdbDatabase, uuid: u32, depth: u16) {
                let group = database.groups.get(&uuid).unwrap();
                println!("{0:1$}>{2}", "", 2*depth as usize, group.name);
                for child in &group.groups {
                    dump_group(database, *child, depth+1);
                }
                for child in &group.entries {
                    let entry = database.entries.get(&child).unwrap();
                    println!("{0:1$}  -{2}", "", 2*depth as usize, entry.title);
                }
            }
            dump_group(&database, root_group_uuid, 0);

            return Ok(());
        },
        // 0xB54BFB66 => {
        //     // XXX Untested
        //     let _ = writeln!(stderr, "KeePass 2.x Beta files not supported\n");
        //     process::exit(1);
        // },
        0xB54BFB67 | 0xB54BFB66 => {
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
        1 => {
            custom_data.insert(KDF_PARAM_UUID.to_string(), kdf_aes_kdbx3.as_bytes().to_vec());
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
    enum Compression {
        None,
        Gzip,
    }
    let compress = match compression_flags {
        0 => {
            // XX Untested
            let _ = writeln!(stderr, "Unsupported no compressed file\n");
            //process::exit(1);
            Compression::None
        },
        1 => {
            println!("Gzip compression");
            Compression::Gzip
        },
        _ => {
            // XX Untested
            let _ = writeln!(stderr, "Unsupported compression method\n");
            process::exit(1);
        },
    };

    let master_seed = &tlvs[&4u8];
    let encryption_iv = &tlvs[&7u8];

    //let mut header = vec![];
    let mut context = Context::new(&SHA256);
    let pos = file.seek(SeekFrom::Current(0))?;
    file.seek(SeekFrom::Start(0))?;
    let mut header = vec![0; (pos) as usize];
    file.read_exact(&mut header)?;
    file.seek(SeekFrom::Start(pos))?;
    context.update(&header);
    let digest = context.finish();
    if major_version == 4 {
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
            /* KDBX 3.x format encrypts the database after breaking
             * the stream into blocks */
            let mut ciphertext = vec![];
            file.read_to_end(&mut ciphertext)?;
            let data = decrypt(Cipher::aes_256_cbc(), &master_key, Some(encryption_iv), &ciphertext).unwrap();
            let mut c = Cursor::new(data);

            /* Start stream header is used to verify successful decrypt */
            let mut start_stream = vec![0; 32];
            c.read_exact(&mut start_stream)?;
            assert_eq!(&start_stream, &tlvs[&9u8]);
            println!("Master Key appears valid");

            let mut buf = vec![];
            for idx in 0.. {
                println!("Block {}", idx);
                let block_id = c.read_u32::<LittleEndian>()?;
                assert_eq!(idx as u32, block_id);
                let mut block_hash_expected = vec![0; 32];
                c.read_exact(&mut block_hash_expected)?;
                let block_size = c.read_u32::<LittleEndian>()?;
                let mut block_data = vec![0; block_size as usize];
                c.read_exact(&mut block_data)?;
                let mut context = Context::new(&SHA256);
                context.update(&block_data);
                let block_hash = context.finish().as_ref().to_owned();
                if block_size == 0 {
                    break;
                }
                assert_eq!(block_hash_expected, block_hash, "Failed hash");
                buf.extend(block_data);
            }
            let mut gz:Box<dyn Read> = match compress {
                Compression::Gzip => Box::new(GzDecoder::new(Cursor::new(buf))),
                Compression::None => Box::new(Cursor::new(buf)),
            };
            let mut xml_file = File::create("data2.xml")?;
            let mut contents = String::new();
            gz.read_to_string(&mut contents)?;
            let _ = xml_file.write(&contents.as_bytes());
            // println!("{:#?}", &contents);
            if &contents[0..3] == "\u{feff}" {
                contents = contents[3..].to_string();
            }
            let package = parser::parse(&contents).unwrap();
            let document = package.as_document();
            let header_hash = evaluate_xpath(&document, "/KeePassFile/Meta/HeaderHash/text()").expect("Missing header hash");
            if header_hash.string() != "" {
                println!("Header Hash: '{}'", header_hash.string());
                let expected_hash = decode(&header_hash.string()).expect("Valid base64");
                if expected_hash != digest.as_ref() {
                    let _ = writeln!(stderr, "Possible header corruption\n");
                    process::exit(1);
                }
            }
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
    let timestamp = Cursor::new(decode(&database_name_changed_node.string()).expect("Valid base64")).read_i64::<LittleEndian>()? - KDBX4_TIME_OFFSET;
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

    let content_cursor = Cursor::new(&contents);
    let mut reader = ParserConfig::new()
        .cdata_to_characters(true)
        .create_reader(content_cursor);
    loop {
        let event = reader.next().unwrap();
        match event {
            XmlEvent::StartDocument { .. } => { println!("Start"); },
            XmlEvent::StartElement { name: _, .. } => { decode_document(&mut reader).map_err(|x| ::std::io::Error::new(::std::io::ErrorKind::Other, x))?; },
            XmlEvent::EndDocument => { println!("End"); break; },
            _ => {},
        }
    }

    //#[derive(Debug, Serialize, Deserialize, YaSerialize, YaDeserialize, PartialEq)]
    #[derive(Debug, YaSerialize, YaDeserialize, PartialEq)]
    //#[serde(rename_all = "PascalCase")]
    struct KeePassFile {
        //#[serde(rename = "Meta")]
        #[yaserde(rename = "Meta")]
        meta: Meta,
        #[yaserde(rename = "Root")]
        root: Vec<Group>,
    }

    #[derive(Debug, Default, PartialEq)]
    struct CustomData(HashMap<String, String>);

    /*
    fn consume_element<R: Read>(reader: &mut yaserde::de::Deserializer<R>, mut event: XmlEvent) -> Result<(), String> {
        let mut elements = vec![];

        loop {
            match event {
                XmlEvent::StartDocument { .. } => {
                    return Err("Malformed XML document".to_string());
                },
                XmlEvent::EndDocument { .. } => {
                    return Err("Malformed XML document".to_string());
                },
                XmlEvent::StartElement { name, .. } => {
                    elements.push(name);
                },
                XmlEvent::EndElement { name, .. } => {
                    let start_tag = elements.pop().expect("Can't consume a bare end element");
                    if start_tag != name {
                        return Err(format!("Start tag <{}> mismatches end tag </{}>", start_tag, name));
                    }
                },
                _ => {
                    // Consume any PI, text, comment, or cdata node
                    return Ok(());
                },
            };
            if elements.len() == 0 {
                return Ok(());
            }
            event = reader.next_event()?;
        }
    }
    */

    impl YaDeserialize for CustomData {
        fn deserialize<R: Read>(reader: &mut yaserde::de::Deserializer<R>) -> Result<Self, String> {
            let _name = match reader.next_event()? {
                XmlEvent::StartElement { name, .. } => name,
                _ => { return Err("No element next".to_string()); },
            };
            println!("Starting event");

            let mut data = HashMap::new();

            loop {
                //println!("Event: {:?}", reader.next_event());
                let next = reader.peek()?;
                match next {
                    XmlEvent::EndElement { .. } => {
                        return Ok(CustomData(data))
                    }
                    _ => {}
                }
                match dbg!(reader.next_event()?) {
                    XmlEvent::StartDocument { .. } => { return Err("Malformed XML document".to_string()); },
                    XmlEvent::EndDocument => { return Err("Malformed XML document".to_string()); },
                    XmlEvent::StartElement { name, .. }
                      if name.local_name == "Item" => {
                        let mut key = String::new();
                        let mut value = String::new();
                        loop {
                            match reader.next_event()? {
                                XmlEvent::StartElement { name, .. }
                                  if name.local_name == "Key" => {
                                    loop {
                                        match reader.next_event()? {
                                            XmlEvent::Characters(k) => {
                                                key = k;
                                            },
                                            XmlEvent::EndElement { name }
                                              if name.local_name == "Key" => {
                                                break;
                                            },
                                            XmlEvent::EndElement { .. } => {
                                                return Err("Malformed XML document".to_string());
                                            },
                                            _ => { panic!("Bad document parsing"); },
                                        }
                                    }
                                },
                                XmlEvent::StartElement { name, .. }
                                  if name.local_name == "Value" => {
                                    loop {
                                        match reader.next_event()? {
                                            XmlEvent::Characters(k) => {
                                                value = k;
                                            },
                                            XmlEvent::EndElement { name }
                                              if name.local_name == "Value" => {
                                                break;
                                            },
                                            XmlEvent::EndElement { .. } => {
                                                return Err("Malformed XML document".to_string());
                                            },
                                            _ => { panic!("Bad document parsing"); },
                                        }
                                    }
                                },
                                XmlEvent::EndElement { name }
                                  if name.local_name == "Item" => {
                                    data.insert(key, value);
                                    break;
                                },
                                XmlEvent::EndElement { .. } => {
                                    return Err("Malformed XML document".to_string());
                                },
                                _ => { panic!("Bad document parsing"); },
                            }
                        }
                    },
                    XmlEvent::StartElement { name: _, .. } => {
                        // TODO Consume this
                    },
                    XmlEvent::EndElement { name }
                      if name.local_name == "CustomData" => {
                        break;
                    },
                    XmlEvent::EndElement { .. } => {
                        return Err("Malformed XML document".to_string());
                    },
                    _ => { panic!("Bad document parsing"); },
                }
            }
            //Err("Fail De".to_string())
            Ok(CustomData(data))
        }
    }

    impl YaSerialize for CustomData {
        fn serialize<W: Write>(&self, writer: &mut yaserde::ser::Serializer<W>) -> Result<(), String> {
            //Err("Fail Ser".to_string())
            //writer.write(xml::writer::events::XmlEvent::comment("A comment"));
            for (key, value) in &self.0 {
                //writer.write(xml::writer::events::XmlEvent::comment("A comment"));
                writer.write(xml::writer::events::XmlEvent::start_element("Item")).map_err(|x| format!("{}", x))?;
                writer.write(xml::writer::events::XmlEvent::start_element("Key")).map_err(|x| format!("{}", x))?;
                writer.write(xml::writer::events::XmlEvent::characters(key)).map_err(|x| format!("{}", x))?;
                writer.write(xml::writer::events::XmlEvent::end_element()).map_err(|x| format!("{}", x))?;
                writer.write(xml::writer::events::XmlEvent::start_element("Value")).map_err(|x| format!("{}", x))?;
                writer.write(xml::writer::events::XmlEvent::characters(value)).map_err(|x| format!("{}", x))?;
                writer.write(xml::writer::events::XmlEvent::end_element()).map_err(|x| format!("{}", x))?;
                writer.write(xml::writer::events::XmlEvent::end_element()).map_err(|x| format!("{}", x))?;
            }
            Ok(())
        }
    }

    #[derive(Debug, PartialEq)]
    struct KdbDate(DateTime<Local>);

    impl Default for KdbDate {
        fn default() -> Self {
            KdbDate(Local::now())
        }
    }

    impl YaDeserialize for KdbDate {
        fn deserialize<R: Read>(reader: &mut yaserde::de::Deserializer<R>) -> Result<Self, String> {
            reader.next_event()?;
            let name = match reader.next_event()? {
                //XmlEvent::StartElement { name, .. } => name,
                XmlEvent::Characters(text) => text,
                _ => "AAAAAAAAAAA=".to_string(),
            };
                //_ => { return Err("No element next".to_string()) }
            println!("Decode: {:?}", name);
            let timestamp = Cursor::new(decode(&name).expect("Valid base64")).read_i64::<LittleEndian>().unwrap() - KDBX4_TIME_OFFSET;
            let datetime: DateTime<Local> = Local.timestamp(timestamp, 0);
            Ok(KdbDate(datetime))
        }
    }

    impl YaSerialize for KdbDate {
        fn serialize<W: Write>(&self, writer: &mut yaserde::ser::Serializer<W>) -> Result<(), String> {
            let mut data = vec![];
            data.write_i64::<LittleEndian>(self.0.timestamp() + KDBX4_TIME_OFFSET).expect("to succeed");
            //let datetime: DateTime<Local> = Local.timestamp(timestamp, 0);
            //let timestamp = Cursor::new(decode(&name).expect("Valid base64")).read_i64::<LittleEndian>().unwrap() - KDBX4_TIME_OFFSET;
            writer.write(xml::writer::events::XmlEvent::start_element("CreationTime")).map_err(|x| format!("{}", x))?;
            writer.write(xml::writer::events::XmlEvent::characters(&encode(&data))).map_err(|x| format!("{}", x))?;
            writer.write(xml::writer::events::XmlEvent::end_element()).map_err(|x| format!("{}", x))?;
            Ok(())
        }
    }

    //#[derive(Debug, Default, Serialize, Deserialize, YaSerialize, YaDeserialize, PartialEq)]
    #[derive(Debug, Default, YaSerialize, YaDeserialize, PartialEq)]
    //#[serde(rename_all = "PascalCase", default)]
    struct Meta {
        #[yaserde(rename = "Generator")]
        generator: String,
        #[yaserde(rename = "DatabaseName")]
        database_name: String,
        #[yaserde(rename = "DatabaseNameChanged")]
        database_name_changed: String,
        #[yaserde(rename = "DatabaseDescription")]
        database_description: String,
        #[yaserde(rename = "DatabaseDescriptionChanged")]
        database_description_changed: String,
        #[yaserde(rename = "DefaultUserName")]
        default_user_name: String,
        #[yaserde(rename = "DefaultUserNameChanged")]
        default_user_name_changed: String,
        #[yaserde(rename = "MaintenanceHistoryDays")]
        maintenance_history_days: String,
        #[yaserde(rename = "Color")]
        color: String,
        #[yaserde(rename = "MasterKeyChanged")]
        master_key_changed: String,
        #[yaserde(rename = "MasterKeyChangeRec")]
        master_key_change_rec: String,
        #[yaserde(rename = "MasterKeyChangeForce")]
        master_key_change_force: String,
        #[yaserde(rename = "MemoryProtection")]
        memory_protection: MemoryProtection,
        #[yaserde(rename = "CustomIcons")]
        custom_icons: String,
        #[yaserde(rename = "RecycleBinEnabled")]
        recycle_bin_enabled: String,
        //#[serde(rename = "RecycleBinUUID")]
        #[yaserde(rename = "RecycleBinUUID")]
        recycle_bin_uuid: Option<String>,
        #[yaserde(rename = "RecycleBinChanged")]
        recycle_bin_changed: String,
        #[yaserde(rename = "EntryTemplatesGroup")]
        entry_templates_group: String,
        #[yaserde(rename = "EntryTemplatesGroupChanged")]
        entry_templates_group_changed: String,
        #[yaserde(rename = "LastSelectedGroup")]
        last_selected_group: String,
        #[yaserde(rename = "LastTopVisibleGroup")]
        last_top_visible_group: String,
        #[yaserde(rename = "HistoryMaxItems")]
        history_max_items: String,
        #[yaserde(rename = "HistoryMaxSize")]
        history_max_size: String,
        #[yaserde(rename = "SettingsChanged")]
        settings_changed: KdbDate,
        #[yaserde(rename = "CustomData")]
        custom_data: CustomData,
    }

    #[derive(Debug, Default, YaSerialize, YaDeserialize, PartialEq)]
    struct Times {
        #[yaserde(rename = "LastModificationTime")]
        last_modification_time: String,
        #[yaserde(rename = "CreationTime")]
        creation_time: KdbDate,
        #[yaserde(rename = "LastAccessTime")]
        last_access_time: String,
        #[yaserde(rename = "ExpiryTime")]
        expiry_time: String,
        #[yaserde(rename = "Expires")]
        expires: String,
        #[yaserde(rename = "UsageCount")]
        usage_count: String,
        #[yaserde(rename = "LocationChanged")]
        location_changed: String,
    }

    #[derive(Debug, Default, YaSerialize, YaDeserialize, PartialEq)]
    struct Group {
        #[yaserde(rename = "UUID")]
        uuid: String,
        #[yaserde(rename = "Name")]
        name: String,
        #[yaserde(rename = "Notes")]
        notes: String,
        #[yaserde(rename = "IconID")]
        icon_id: u32,
        #[yaserde(rename = "Times")]
        times: Times,
        #[yaserde(rename = "IsExpanded")]
        is_expanded: String,
        //<DefaultAutoTypeSequence/>
        #[yaserde(rename = "EnableAutoType")]
        enable_auto_type: String,
        #[yaserde(rename = "EnableSearching")]
        enable_searching: String,
        #[yaserde(rename = "LastTopVisibleEntry")]
        last_top_visible_entry: String,
        #[yaserde(rename = "CustomData")]
        custom_data: CustomData,
        //#[yaserde(rename = "Group")]
        group: Vec<Group>,
        #[yaserde(rename = "Entry")]
        entry: Vec<Entry>,
    }

    #[derive(Debug, Default, YaSerialize, YaDeserialize, PartialEq)]
    struct Entry {
        #[yaserde(rename = "UUID")]
        uuid: String,
        #[yaserde(rename = "IconID")]
        icon_id: u32,
        #[yaserde(rename = "Times")]
        times: Times,
        #[yaserde(rename = "CustomData")]
        custom_data: CustomData,
    }

    //#[derive(Debug, Default, Serialize, Deserialize, YaSerialize, YaDeserialize, PartialEq)]
    #[derive(Debug, Default, YaSerialize, YaDeserialize, PartialEq)]
    //#[serde(rename_all = "PascalCase", default)]
    #[yaserde(default)]
    struct MemoryProtection {
        #[yaserde(rename = "ProtectTitle")]
        protect_title: String,
        #[yaserde(rename = "ProtectUserName")]
        protect_user_name: String,
        #[yaserde(rename = "ProtectPassword")]
        protect_password: String,
        #[yaserde(rename = "ProtectUrl")]
        protect_url: String,
        #[yaserde(rename = "ProtectNotes")]
        protect_notes: String,
    }

    /*
    let mut database: KeePassFile = from_str(&contents).unwrap();
    println!("Database Generator: '{}'", database.meta.generator);
    println!("Database: {:?}", database);
    database.meta.generator = "<Funny>".to_string();
    println!("XML: {:?}", to_string(&database).unwrap());
    */

    //let content_cursor = Cursor::new(&contents);
    //let mut reader = ParserConfig::new()
    //    .cdata_to_characters(true)
    //    .create_reader(content_cursor);
    //let de = yaserde::de::Deserializer::new(reader);
    let mut database: KeePassFile = yaserde::de::from_str(&contents).unwrap();
    database.meta.generator = "<Funny>".to_string();
    println!("Parsed: {:?}", database);
    println!("XML: {:?}", yaserde::ser::to_string(&database).unwrap());

    Ok(())
}
