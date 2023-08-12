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
#[macro_use]
extern crate num_derive;
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

use std::collections::VecDeque;
use std::convert::TryInto;
use std::io::Cursor;
use std::env;
use std::process;
use std::fs::File;
use std::io::{self, SeekFrom};
use std::io::prelude::*;
use std::collections::{BTreeMap, HashMap};
//use std::cell::RefCell;
//use std::rc::Rc;
use std::cmp;

use num_traits::{FromPrimitive, ToPrimitive};

//use hex::ToHex;
// use hex::FromHex;
use hex_literal::hex;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use base64::{decode, encode};
use openssl::error::ErrorStack;
use uuid::{uuid, Uuid};
//use borsh::de::BorshDeserialize;  // try_from_slice()
use ring::digest::{Context, SHA256, SHA512};
use ring::hmac;
use rpassword::read_password;
use openssl::symm::{decrypt, Crypter, Cipher, Mode};
use flate2::read::GzDecoder;
use sxd_document::parser;
use sxd_xpath::{evaluate_xpath, Context as XPathContext, Factory, Value};
use chrono::prelude::*;
use salsa20::Salsa20;
use salsa20::Key as Salsa20_Key;
use salsa20::cipher::{KeyIvInit, StreamCipher};
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
use xml::writer::EventWriter;
use xml::attribute::OwnedAttribute;
use xml::name::OwnedName;
use yaserde::{YaDeserialize, YaSerialize};

use kdbx_derive::{KdbxParse, KdbxSerialize};

//trait KdbxDefault: Default {
//    fn provide_default() -> Self
//        {
//        <Self as Default>::default()
//    }
//}

trait KdbxParse: Sized + Default {
//    fn provide_default() -> Self
//        where Self: Default {
//        <Self as Default>::default()
//    }

    fn parse<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Self, String>;
}

//impl<T: KdbxParse> KdbxParse
//    where T: KdbxParse + Default {
//    fn default() -> Self {

trait KdbxSerialize: Sized {
    fn serialize2<W: Write>(writer: &mut EventWriter<W>, value: Self) -> Result<(), String>;
}

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

#[derive(FromPrimitive, ToPrimitive)]
enum Compression {
    None = 0,
    Gzip = 1,
}

#[derive(FromPrimitive, ToPrimitive)]
enum TlvType {
    End = 0,
    Comment = 1,
    CipherId = 2,
    CompressionFlags = 3,
    MasterSeed = 4,
    TransformSeed = 5,
    TransformRounds = 6,
    EncryptionIv = 7,
    ProtectedStreamKey = 8,
    StreamStartBytes = 9,
    InnerRandomStreamId = 10,
    KdfParameters = 11,
    PublicCustomData = 12,
}

// struct Header {
//     major_version: u16,
//     minor_version: u16,
//     tlvs: BTreeMap<u8, Vec<Vec<u8>>>,
// }

// impl Header {
    fn load_tlvs<R: Read>(input: &mut R, major_version: u16) -> io::Result<(BTreeMap<u8, Vec<Vec<u8>>>, Vec<u8>)> {
        // let minor_version = 0;
        let mut tlvs = BTreeMap::new();
        let mut header_blob = Vec::new();
        loop {
            let mut tlv_header = if major_version == 3 {
                vec![0; 3]
            } else {
                vec![0; 5]
            };
            input.read_exact(&mut tlv_header)?;
            header_blob.extend(&tlv_header);
            let mut header_cursor = Cursor::new(tlv_header);
            let tlv_type = header_cursor.read_u8()?;
            let tlv_len = if major_version <= 3 {
                header_cursor.read_u16::<LittleEndian>()? as u32
            } else {
                header_cursor.read_u32::<LittleEndian>()?
            };
            let mut tlv_data = vec![0; tlv_len as usize];
            input.read_exact(&mut tlv_data)?;
            header_blob.extend(&tlv_data);
            debug!("TLV({}, {}): {:?}", tlv_type, tlv_len, &tlv_data);
            if tlv_type == 0 {
                break;
            }
            let values = match tlvs.get_mut(&tlv_type) {
                Some(v) => v,
                None => {
                    let v = Vec::new();
                    tlvs.insert(tlv_type, v);
                    tlvs.get_mut(&tlv_type).unwrap()
                }
            };
            values.push(tlv_data);
        };
        Ok((tlvs, header_blob))
    }

    fn save_tlvs<W: Write>(output: &mut W, tlvs: &BTreeMap<u8, Vec<Vec<u8>>>, major_version: u16) -> io::Result<Vec<u8>> {
        let mut buf = Cursor::new(Vec::new());
        let term = HashMap::from([(0, vec![vec![]])]);
        for (key, values) in tlvs.iter().chain(term.iter()) {
            for value in values {
                buf.write_u8(*key)?;
                // TODO Check for overflow
                if major_version <= 3 {
                    buf.write_u16::<LittleEndian>(value.len() as u16)?;
                } else {
                    buf.write_u32::<LittleEndian>(value.len() as u32)?;
                }
                buf.write(value)?;
            }
        }
        let bytes = buf.into_inner();
        output.write(&bytes);
        Ok(bytes)
    }
// }

#[derive(PartialEq, Eq, FromPrimitive, ToPrimitive)]
enum MapType {
    None = 0,
    // Byte = 0x02,
    // UInt16 = 0x03,
    UInt32 = 0x04,
    UInt64 = 0x05,
    Bool = 0x08,
    // SByte = 0x0A,
    // Int16 = 0x0B,
    Int32 = 0x0C,
    Int64 = 0x0D,
    // Float = 0x10,
    // Double = 0x11,
    // Decimal = 0x12,
    // Char = 0x17, // 16-bit Unicode character
    String = 0x18,
    ByteArray = 0x42,
}

#[derive(PartialEq, Eq, Debug)]
enum MapValue {
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
    Int32(i32),
    Int64(i64),
    String(String),
    ByteArray(Vec<u8>),
}

impl From<&MapValue> for MapType {
    fn from(value: &MapValue) -> Self {
        match value {
            MapValue::Bool(_) => MapType::Bool,
            MapValue::Int32(_) => MapType::Int32,
            MapValue::Int64(_) => MapType::Int64,
            MapValue::UInt32(_) => MapType::UInt32,
            MapValue::UInt64(_) => MapType::UInt64,
            MapValue::String(_) => MapType::String,
            MapValue::ByteArray(_) => MapType::ByteArray,
        }
    }
}

fn load_map(tlv_data: &[u8]) -> io::Result<HashMap::<String, MapValue>> {
    let mut custom_data = HashMap::new();
    let kdf_parameters = &tlv_data;
    let mut c = Cursor::new(kdf_parameters);
    let variant_minor = c.read_u8()?;
    let variant_major = c.read_u8()?;
    if variant_major != 1 {
        let _ = eprintln!(
                 "Unsupported variant dictionary version ({}.{})\n",
                 variant_major, variant_minor);
        return Err(io::Error::new(io::ErrorKind::Other, "Unsupported variant"));
    };

    loop {
        let item_type = MapType::from_u8(c.read_u8()?).ok_or(io::Error::new(io::ErrorKind::Other, "Unknown type"))?;
        if item_type == MapType::None {
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
        let item_value = match item_type {
            MapType::Bool => {
                if item_value.len() != 1 {
                    return Err(io::Error::new(io::ErrorKind::Unsupported, "Invalid bool value"));
                }
                MapValue::Bool(item_value[0] != 0)
            },
            MapType::Int32 => {
                MapValue::Int32(i32::from_le_bytes(item_value.try_into().map_err(|_| io::Error::new(io::ErrorKind::Unsupported, "Invalid i32 value"))?))
            },
            MapType::Int64 => {
                MapValue::Int64(i64::from_le_bytes(item_value.try_into().map_err(|_| io::Error::new(io::ErrorKind::Unsupported, "Invalid i64 value"))?))
            },
            MapType::UInt32 => {
                MapValue::UInt32(u32::from_le_bytes(item_value.try_into().map_err(|_| io::Error::new(io::ErrorKind::Unsupported, "Invalid u32 value"))?))
            },
            MapType::UInt64 => {
                MapValue::UInt64(u64::from_le_bytes(item_value.try_into().map_err(|_| io::Error::new(io::ErrorKind::Unsupported, "Invalid u64 value"))?))
            },
            MapType::String => {
                MapValue::String(String::from_utf8(item_value).map_err(|_| io::Error::new(io::ErrorKind::Unsupported, "Invalid string value"))?)
            },
            MapType::ByteArray => {
                MapValue::ByteArray(item_value)
            },
            MapType::None => {
                unreachable!()
            },
        };
        custom_data.insert(item_key_str.to_owned().to_string(), item_value);
    }
    Ok(custom_data)
}

fn save_map(map: &HashMap::<String, MapValue>) -> Vec<u8> {
    let variant_major = 1;
    let variant_minor = 0;
    let mut output = Cursor::new(Vec::new());
    output.write_u8(variant_minor).unwrap();
    output.write_u8(variant_major).unwrap();
    for (k, v) in map {
        output.write_u8(MapType::from(v).to_u8().unwrap()).unwrap();
        output.write_u32::<LittleEndian>(k.len() as u32).unwrap();
        output.write(k.as_bytes()).unwrap();
        let item_value = match v {
            MapValue::Bool(v) => {
                vec![if *v { 1 } else { 0 }]
            },
            MapValue::Int32(v) => {
                v.to_le_bytes().to_vec()
            },
            MapValue::Int64(v) => {
                v.to_le_bytes().to_vec()
            },
            MapValue::UInt32(v) => {
                v.to_le_bytes().to_vec()
            },
            MapValue::UInt64(v) => {
                v.to_le_bytes().to_vec()
            },
            MapValue::String(v) => {
                v.as_bytes().to_vec()
            },
            MapValue::ByteArray(v) => {
                v.clone()
            },
        };
        output.write_u32::<LittleEndian>(item_value.len() as u32).unwrap();
        output.write(&item_value).unwrap();
    }
    output.write_u8(0);  // End of dictionary
    output.into_inner()
}

struct BlockReader<R: Read> {
    index: u64,
    // block_size: u32,
    hmac_key_base: Vec<u8>,
    output: R,
    buf: VecDeque<u8>,
    complete: bool,
}

impl<R: Read> BlockReader<R> where {
    // const DEFAULT_BLOCK_SIZE: u32 = 1024*1024;

    fn new(key: &[u8], output: R) -> Self {
        Self {
            index: 0,
            // block_size: Self::DEFAULT_BLOCK_SIZE,
            hmac_key_base: key.to_owned(),
            output,
            // buf: vec![0u8; 12],  /* Room for 64-bit block index and 32-bit size */
            buf: VecDeque::new(),
            complete: false,
        }
    }

    fn load_next_block(&mut self) -> io::Result<()> {
        println!("Block {}", self.index);
        let mut hmac_tag: [u8; 32] = [0; 32];
        // if major_version == 4 {
            self.output.read_exact(&mut hmac_tag)?;
        // } else {
        //     /* KDBX 3.x format encrypts the database after breaking
        //     * the stream into blocks */
        //     let mut ciphertext = vec![];
        //     self.output.read_to_end(&mut ciphertext)?;
        //     let data = decrypt(Cipher::aes_256_cbc(), &master_key, Some(encryption_iv), &ciphertext).unwrap();
        //     let mut c = Cursor::new(data);

        //     /* Start stream header is used to verify successful decrypt */
        //     let mut start_stream = vec![0; 32];
        //     c.read_exact(&mut start_stream)?;
        //     assert_eq!(&start_stream, &tlvs[&9u8]);
        //     println!("Master Key appears valid");

        //     let mut buf = vec![];
        //     for self.index in 0.. {
        //         println!("Block {}", self.index);
        //         let block_id = c.read_u32::<LittleEndian>()?;
        //         assert_eq!(self.index as u32, block_id);
        //         let mut block_hash_expected = vec![0; 32];
        //         c.read_exact(&mut block_hash_expected)?;
        //         let block_size = c.read_u32::<LittleEndian>()?;
        //         let mut block_data = vec![0; block_size as usize];
        //         c.read_exact(&mut block_data)?;
        //         let mut context = Context::new(&SHA256);
        //         context.update(&block_data);
        //         let block_hash = context.finish().as_ref().to_owned();
        //         if block_size == 0 {
        //             break;
        //         }
        //         assert_eq!(block_hash_expected, block_hash, "Failed hash");
        //         buf.extend(block_data);
        //     }
        //     let mut gz:Box<dyn Read> = match compress {
        //         Compression::Gzip => Box::new(GzDecoder::new(Cursor::new(buf))),
        //         Compression::None => Box::new(Cursor::new(buf)),
        //     };
        //     let mut xml_file = File::create("data2.xml")?;
        //     let mut contents = String::new();
        //     gz.read_to_string(&mut contents)?;
        //     let _ = xml_file.write(&contents.as_bytes());
        //     // println!("{:#?}", &contents);
        //     if &contents[0..3] == "\u{feff}" {
        //         contents = contents[3..].to_string();
        //     }
        //     let package = parser::parse(&contents).unwrap();
        //     let document = package.as_document();
        //     let header_hash = evaluate_xpath(&document, "/KeePassFile/Meta/HeaderHash/text()").expect("Missing header hash");
        //     if header_hash.string() != "" {
        //         println!("Header Hash: '{}'", header_hash.string());
        //         let expected_hash = decode(&header_hash.string()).expect("Valid base64");
        //         if expected_hash != digest.as_ref() {
        //             let _ = writeln!(stderr, "Possible header corruption\n");
        //             process::exit(1);
        //         }
        //     }
        //     return Ok(());
        // }
        let block_size = self.output.read_u32::<LittleEndian>()?;
        if block_size == 0 {
            self.complete = true;
            return Ok(());
        }
        let mut block = vec![0; block_size as usize];
        self.output.read_exact(&mut block)?;

        let mut hmac_context = Context::new(&SHA512);
        let mut buf = Cursor::new(Vec::new());
        buf.write_u64::<LittleEndian>(self.index)?;
        self.index += 1;
        hmac_context.update(buf.get_ref());
        hmac_context.update(&self.hmac_key_base);
        let hmac_key = hmac_context.finish().as_ref().to_owned();
        buf.write_u32::<LittleEndian>(block_size)?;
        buf.write(&block)?;
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key);
        println!("Verifying HMAC");
        hmac::verify(&hmac_key, buf.get_ref(), &hmac_tag).unwrap();
        println!("Complete");
        self.buf = block.into();
        Ok(())
    }
}

impl<R: Read> Read for BlockReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.complete {
            return Ok(0)
        } else if self.buf.len() == 0 {
            self.load_next_block()?;
        }
        let mut index = 0;
        if index >= buf.len() {
            return Ok(index)
        }
        while let Some(val) = self.buf.pop_front() {
            buf[index] = val;
            index += 1;
            if index >= buf.len() {
                return Ok(index);
            }
        }
        Ok(index)
    }
}

struct BlockWriter<W: Write> {
    index: u64,
    block_size: u32,
    hmac_key_base: Vec<u8>,
    output: W,
    buf: Vec<u8>,
}

impl<W: Write> BlockWriter<W> where {
    const DEFAULT_BLOCK_SIZE: u32 = 1024*1024;

    fn new(key: &[u8], output: W) -> Self {
        Self {
            index: 0,
            block_size: Self::DEFAULT_BLOCK_SIZE,
            hmac_key_base: key.to_owned(),
            output,
            // buf: vec![0u8; 12],  /* Room for 64-bit block index and 32-bit size */
            buf: Vec::new(),
        }
    }
}

impl<W: Write> Write for BlockWriter<W> {
    fn flush(&mut self) -> io::Result<()> {
        let mut hmac_context = Context::new(&SHA512);
        let mut key_buf = Cursor::new(Vec::new());
        key_buf.write_u64::<LittleEndian>(self.index)?;
        self.index += 1;
        hmac_context.update(key_buf.get_ref());
        hmac_context.update(&self.hmac_key_base);
        let hmac_key = hmac_context.finish().as_ref().to_owned();
        key_buf.write_u32::<LittleEndian>(self.buf.len() as u32)?;
        key_buf.write(&self.buf)?;
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key);
        // println!("Verifying HMAC");
        let hmac_tag = hmac::sign(&hmac_key, key_buf.get_ref());
        // println!("Complete");
        self.output.write(hmac_tag.as_ref())?;
        self.output.write_u32::<LittleEndian>(self.buf.len() as u32)?;
        self.output.write(&self.buf)?;
        self.buf.truncate(0);
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = cmp::min(self.block_size as usize  - cmp::min(self.buf.len(), self.block_size as usize), buf.len());
        self.buf.extend(&buf[..remaining]);
        if self.buf.len() >= self.block_size as usize {
            self.flush()?;
        }
        Ok(remaining)
        // let mut offset = 0;
        // while offset < self.buf.len() {
        //     let mut count = std::cmp::max(Self::DEFAULT_BLOCK_SIZE as usize - offset;
        //     if count > buf.len() {
        //         count = buf.len();
        //     }
        //     self.buf.extend(&buf[offset..offset+count]);
        //     offset += count;
        //     if self.buf.len() >= Self::DEFAULT_BLOCK_SIZE as usize {
        //         self.flush()?;
        //     }
        // }
        // Ok(buf.len())
    }
}

#[derive(Debug)]
struct CryptoError {
    error: ErrorStack,
}

impl From<ErrorStack> for CryptoError {
    fn from(error: ErrorStack) -> Self {
        Self {
            error,
        }
    }
}

struct Crypto<W: Write> {
    crypter: Crypter,
    output: W,
    buf: Vec<u8>,
    block_size: usize,
}

impl<W: Write> Crypto<W> {
    fn new(cipher: Cipher, key: &[u8], iv: Option<&[u8]>, output: W) -> Result<Self, CryptoError> {
        Ok(Self {
            crypter: Crypter::new(cipher, Mode::Encrypt, key, iv)?,
            output,
            buf: Vec::new(),
            block_size: cipher.block_size(),
        })
    }
}

impl<W: Write> Drop for Crypto<W> {
    fn drop(&mut self) {
        let rest = self.crypter.finalize(&mut self.buf).expect("Failed to finalize encryption");
        self.output.write_all(&self.buf[..rest]).expect("Failed to flush");
    }
}

impl<W: Write> Write for Crypto<W> {
    fn flush(&mut self) -> io::Result<()> {
        // TODO Call lower layer
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.resize(data.len() + self.block_size, 0);
        let count = self.crypter.update(data, &mut self.buf)?;
        self.output.write_all(&self.buf[..count])?;
        self.buf = self.buf[count..].to_vec();
        Ok(data.len())
    }
}

struct CryptoReader<R: Read> {
    crypter: Crypter,
    output: R,
    buf: Vec<u8>,
    block_size: usize,
}

impl<R: Read> CryptoReader<R> {
    fn new(cipher: Cipher, key: &[u8], iv: Option<&[u8]>, output: R) -> Result<Self, CryptoError> {
        Ok(Self {
            crypter: Crypter::new(cipher, Mode::Decrypt, key, iv)?,
            output,
            buf: Vec::new(),
            block_size: cipher.block_size(),
        })
    }
}

// impl<R: Read> Drop for CryptoReader<R> {
//     fn drop(&mut self) {
//         let rest = self.crypter.finalize(&mut self.buf).expect("Failed to finalize encryption");
//         self.output.write_all(&self.buf[..rest]).expect("Failed to flush");
//     }
// }

// impl<R: Read> Read for CryptoReader<R> {
//     fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
//         self.buf.resize(data.len() + self.block_size, 0);
//         let count = self.crypter.update(data, &mut self.buf)?;
//         self.output.write_all(&self.buf[..count])?;
//         self.buf = self.buf[count..].to_vec();
//         Ok(data.len())
//     }
// }

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

trait Kdf {
    fn uuid(&self) -> Uuid;
    fn randomize(&mut self);
    fn transform_key(&self, composite_key: &[u8]) -> io::Result<Vec<u8>>;
    fn save(&self, custom_data: &mut HashMap::<String, MapValue>);
}

struct AesKdf {
    salt: [u8; 32],
    rounds: u64,
}

impl AesKdf {
    fn load(custom_data: &HashMap::<String, MapValue>) -> io::Result<Self> {
            // let salt = &custom_data[KDF_PARAM_SALT];
            // let mut c = custom_data[KDF_PARAM_ROUNDS];
        match (&custom_data[KDF_PARAM_SALT], &custom_data[KDF_PARAM_ROUNDS]) {
            (MapValue::ByteArray(ref salt), MapValue::UInt64(rounds)) =>
                Ok(AesKdf { salt: salt.clone().try_into().unwrap()/*From::<Vec<u8>>::try_into(salt.clone()).unwrap()*/, rounds: *rounds }),
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

    fn save(&self, custom_data: &mut HashMap::<String, MapValue>) {
        custom_data.insert(KDF_PARAM_ROUNDS.to_string(), MapValue::UInt64(self.rounds));
        custom_data.insert(KDF_PARAM_SALT.to_string(), MapValue::ByteArray(self.salt.into()));
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


const KDF_AES_KDBX3: Uuid = uuid!("c9d9f39a-628a-4460-bf74-0d08c18a4fea");
const KDF_AES_KDBX4: Uuid = uuid!("7c02bb82-79a7-4ac0-927d-114a00648238");
const KDF_ARGON2_D : Uuid = uuid!("ef636ddf-8c29-444b-91f7-a9a403e30a0c");
const KDF_ARGON2_ID: Uuid = uuid!("9e298b19-56db-4773-b23d-fc3ec6f0a1e6");

const CIPHER_ID_AES128_CBC : Uuid =  uuid!("61ab05a1-9464-41c3-8d74-3a563df8dd35");
const CIPHER_ID_AES256_CBC : Uuid =  uuid!("31c1f2e6-bf71-4350-be58-05216afc5aff");
const CIPHER_ID_TWOFISH_CBC: Uuid =  uuid!("ad68f29f-576f-4bb9-a36a-d47af965346c");
const CIPHER_ID_CHACHA20   : Uuid =  uuid!("d6038a2b-8b6f-4cb5-a524-339a31dbb59a");


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

fn encode_optional_string<W: Write>(writer: &mut EventWriter<W>, value: Option<&str>) -> Result<(), String> {
    if let Some(contents) = value {
        writer.write(xml::writer::XmlEvent::characters(contents)).map_err(|_|"".to_string())
    } else {
        Ok(())
    }
}

fn decode_string<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<String, String> {
    decode_optional_string(reader, name, attributes).map(|x| x.unwrap_or_else(|| "".into()))
}

impl KdbxParse for String {
    fn parse<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Self, String> {
        decode_string(reader, name, attributes)
    }
}

fn encode_string<W: Write>(writer: &mut EventWriter<W>, value: &str) -> Result<(), String> {
    encode_optional_string(writer, Some(value))
}

impl KdbxSerialize for String {
    fn serialize2<W: Write>(writer: &mut EventWriter<W>, value: Self) -> Result<(), String> {
        encode_string(writer, &value)
    }
}

fn decode_optional_bool<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Option<bool>, String> {
    decode_optional_string(reader, name, attributes).map(|x| x.map(|y| y.eq_ignore_ascii_case("true")))
}

fn encode_optional_bool<W: Write>(writer: &mut EventWriter<W>, value: Option<bool>) -> Result<(), String> {
    encode_optional_string(writer, value.map(|x| if x { "true" } else { "false"}))
}

fn decode_bool<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<bool, String> {
    decode_optional_bool(reader, name, attributes).map(|x| x.unwrap_or(false))
}

impl KdbxParse for bool {
    fn parse<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Self, String> {
        decode_bool(reader, name, attributes)
    }
}

fn encode_bool<W: Write>(writer: &mut EventWriter<W>, value: bool) -> Result<(), String> {
    encode_optional_bool(writer, Some(value))
}

impl KdbxSerialize for bool {
    fn serialize2<W: Write>(writer: &mut EventWriter<W>, value: Self) -> Result<(), String> {
        encode_bool(writer, value)
    }
}

fn decode_optional_i64<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Option<i64>, String> {
    decode_optional_string(reader, name, attributes).map(|x| x.map(|y| y.parse().unwrap_or(0)))
}

fn encode_optional_i64<W: Write>(writer: &mut EventWriter<W>, value: Option<i64>) -> Result<(), String> {
    encode_optional_string(writer, value.map(|x| format!("{}", x)).as_deref())
}

fn decode_i64<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<i64, String> {
    decode_optional_i64(reader, name, attributes).map(|x| x.unwrap_or(0))
}

impl KdbxParse for i64 {
    fn parse<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Self, String> {
        decode_i64(reader, name, attributes)
    }
}

fn encode_i64<W: Write>(writer: &mut EventWriter<W>, value: i64) -> Result<(), String> {
    encode_optional_i64(writer, Some(value))
}

impl KdbxSerialize for i64 {
    fn serialize2<W: Write>(writer: &mut EventWriter<W>, value: Self) -> Result<(), String> {
        encode_i64(writer, value)
    }
}

impl KdbxParse for i32 {
    fn parse<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Self, String> {
        Ok(decode_i64(reader, name, attributes)? as i32)
    }
}

impl KdbxSerialize for i32 {
    fn serialize2<W: Write>(writer: &mut EventWriter<W>, value: Self) -> Result<(), String> {
        encode_i64(writer, value as i64)
    }
}

impl KdbxParse for u32 {
    fn parse<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Self, String> {
        Ok(decode_i64(reader, name, attributes)? as u32)
    }
}

impl KdbxSerialize for u32 {
    fn serialize2<W: Write>(writer: &mut EventWriter<W>, value: Self) -> Result<(), String> {
        encode_i64(writer, value as i64)
    }
}

static mut KDBX4: bool = true;
const KDBX4_TIME_OFFSET : i64 = 62135596800;
fn decode_optional_datetime<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Option<DateTime<Utc>>, String> {
    let is_new = unsafe { KDBX4 };
    if is_new {
        decode_optional_string(reader, name, attributes).map(|x| x.map(|y| Utc.timestamp(Cursor::new(decode(&y).expect("Valid base64")).read_i64::<LittleEndian>().unwrap() - KDBX4_TIME_OFFSET, 0)))
    } else {
        decode_optional_string(reader, name, attributes).map(|x| x.map(|y| DateTime::parse_from_rfc3339(&y).expect("failed to parse timestamp").with_timezone(&Utc)))
    }
}

impl KdbxParse for Option<DateTime<Utc>> {
    fn parse<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Self, String> {
        decode_optional_datetime(reader, name, attributes)
    }
}

fn encode_optional_datetime<W: Write>(writer: &mut EventWriter<W>, value: Option<DateTime<Utc>>) -> Result<(), String> {
    encode_optional_string(writer, value.map(|x| encode(&(x.timestamp() + KDBX4_TIME_OFFSET).to_le_bytes())).as_deref())
}

impl KdbxSerialize for Option<DateTime<Utc>> {
    fn serialize2<W: Write>(writer: &mut EventWriter<W>, value: Self) -> Result<(), String> {
        encode_optional_datetime(writer, value)
    }
}

fn decode_datetime<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<DateTime<Utc>, String> {
    decode_optional_datetime(reader, name, attributes).map(|x| x.expect("missing date"))
}

//impl KdbxDefault for DateTime<Utc> {
//    fn provide_default() -> Self {
//        Utc::now()
//    }
//}

impl KdbxParse for DateTime<Utc> {
    fn parse<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Self, String> {
        decode_datetime(reader, name, attributes)
    }
}

fn encode_datetime<W: Write>(writer: &mut EventWriter<W>, value: DateTime<Utc>) -> Result<(), String> {
    encode_optional_datetime(writer, Some(value))
}

impl KdbxSerialize for DateTime<Utc> {
    fn serialize2<W: Write>(writer: &mut EventWriter<W>, value: Self) -> Result<(), String> {
        encode_datetime(writer, value)
    }
}

//fn decode_i64<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<DateTime<Utc>, String> {
    //decode_optional_i64(reader, name, attributes).map(|x| x.unwrap_or(0))
//}

fn decode_optional_uuid<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Option<Uuid>, String> {
    decode_optional_string(reader, name, attributes).map(|x| x.map(|y| Uuid::from_slice(&decode(&y).expect("Valid base64")).unwrap()))
}

fn encode_optional_uuid<W: Write>(writer: &mut EventWriter<W>, value: Option<Uuid>) -> Result<(), String> {
    encode_optional_string(writer, value.map(|x| encode(x.as_ref())).as_deref())
}

impl KdbxParse for Option<Uuid> {
    fn parse<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Self, String> {
        decode_optional_uuid(reader, name, attributes)
    }
}

impl KdbxSerialize for Option<Uuid> {
    fn serialize2<W: Write>(writer: &mut EventWriter<W>, value: Self) -> Result<(), String> {
        encode_optional_uuid(writer, value)
    }
}

fn decode_uuid<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Uuid, String> {
    decode_optional_uuid(reader, name, attributes).map(|x| x.unwrap_or_else(|| Uuid::default()))
}

fn encode_uuid<W: Write>(writer: &mut EventWriter<W>, value: Uuid) -> Result<(), String> {
    encode_optional_uuid(writer, Some(value))
}

impl KdbxParse for Uuid {
    fn parse<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Self, String> {
        decode_uuid(reader, name, attributes)
    }
}

impl KdbxSerialize for Uuid {
    fn serialize2<W: Write>(writer: &mut EventWriter<W>, value: Self) -> Result<(), String> {
        encode_uuid(writer, value)
    }
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

fn encode_item<W: Write>(writer: &mut EventWriter<W>, value: (&str, &str))-> Result<(), String> {
    writer.write(xml::writer::XmlEvent::start_element("Item")).map_err(|_|"")?;
    writer.write(xml::writer::XmlEvent::start_element("Key")).map_err(|_|"")?;
    encode_string(writer, value.0)?;
    writer.write(xml::writer::XmlEvent::end_element()).map_err(|_|"")?;
    writer.write(xml::writer::XmlEvent::start_element("Value")).map_err(|_|"")?;
    encode_string(writer, value.1)?;
    writer.write(xml::writer::XmlEvent::end_element()).map_err(|_|"")?;
    writer.write(xml::writer::XmlEvent::end_element()).map_err(|_|"")?;
    Ok(())
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

fn encode_custom_data<W: Write>(writer: &mut EventWriter<W>, map: HashMap<String, String>) -> Result<(), String> {
    for (key, value) in map.iter() {
        encode_item(writer, (key, value))?;
    }
    Ok(())
}

#[derive(Debug, Default, KdbxParse, KdbxSerialize)]
struct MemoryProtection {
    protect_title: bool,
    protect_user_name: bool,
    protect_password: bool,
    #[kdbx(element="ProtectURL")]
    protect_url: bool,
    protect_notes: bool,
}

#[derive(Debug, Default, KdbxParse, KdbxSerialize)]
struct Meta {
    generator: String,
    database_name: String,
    database_name_changed: Option<DateTime<Utc>>,
    database_description: String,
    database_description_changed: Option<DateTime<Utc>>,
    default_user_name: String,
    default_user_name_changed: Option<DateTime<Utc>>,
    maintenance_history_days: u32,
    color: String,
    master_key_changed: Option<DateTime<Utc>>,
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
    settings_changed: Option<DateTime<Utc>>,
    custom_data: HashMap<String, String>,
}

impl KdbxParse for HashMap<String, String> {
    fn parse<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<Self, String> {
        decode_custom_data(reader, name, attributes)
    }
}

impl KdbxSerialize for HashMap<String, String> {
    fn serialize2<W: Write>(writer: &mut EventWriter<W>, value: Self) -> Result<(), String> {
        encode_custom_data(writer, value)
    }
}

#[derive(Debug, Default, PartialEq, KdbxParse, KdbxSerialize)]
//#[derive(Debug, Default, KdbxParse)]
struct Times {
    last_modification_time: DateTime<Utc>,
    creation_time: DateTime<Utc>,
    last_access_time: DateTime<Utc>,
    expiry_time: DateTime<Utc>,
    expires: bool,
    usage_count: i32,
    location_changed: DateTime<Utc>,
}

#[derive(Debug, Default, KdbxParse, KdbxSerialize)]
struct Group {
    #[kdbx(element="UUID")]
    uuid: Uuid,
    name: String,
    notes: String,
    #[kdbx(element="IconID")]
    icon_id: u32,
    times: Times,
    is_expanded: bool,
    //<DefaultAutoTypeSequence/>
    //_enable_auto_type: String,
    //_enable_searching: String,
    last_top_visible_entry: Uuid,
    //custom_data: CustomData,
    #[kdbx(flatten)]
    group: Vec<Group>,
    #[kdbx(flatten)]
    entry: Vec<Entry>,
}

#[derive(Debug, Default, PartialEq, KdbxParse, KdbxSerialize)]
struct Entry {
    #[kdbx(element="UUID")]
    uuid: String,
    #[kdbx(element="IconID")]
    icon_id: u32,
    foreground_color: String,
    background_color: String,
    #[kdbx(element="OverrideURL")]
    override_url: String,
    tags: String,
    times: Times,
    // custom_data: CustomData,
    history: Vec<Entry>,
}

#[derive(Default, KdbxParse, KdbxSerialize)]
struct KeePassFile {
    meta: Meta,
    root: Vec<Group>,
}

fn decode_memory_protection_old<R: Read>(reader: &mut EventReader<R>, name: OwnedName, _attributes: Vec<OwnedAttribute>) -> Result<MemoryProtection, String> {
    let mut elements = vec![name];
    //elements.push(name);

    let mut protect_title = false;
    let mut protect_user_name = false;
    let mut protect_password = false;
    let mut protect_url = false;
    let mut protect_notes = false;
    while elements.len() > 0 {
        let event = reader.next().map_err(|_|"")?;
        println!("Decode mem...");
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

fn decode_meta_old<R: Read>(reader: &mut EventReader<R>) -> Result<Meta, String> {
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
    let mut database_description_changed = None;
    let mut default_user_name = String::new();
    let mut default_user_name_changed = None;
    let mut maintenance_history_days = 0;
    let color = String::new();
    let mut master_key_changed = None;
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
    let mut settings_changed = None;
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
              if name.local_name == "DatabaseDescriptionChanged" => {
                database_description_changed = decode_optional_datetime(reader, name, attributes)?;
                println!("DatabaseDescriptionChanged: {:?}", database_description_changed);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "DefaultUserName" => {
                default_user_name = decode_string(reader, name, attributes)?;
                println!("DefaultUserName: {:?}", default_user_name);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "DefaultUserNameChanged" => {
                default_user_name_changed = decode_optional_datetime(reader, name, attributes)?;
                println!("DefaultUserNameChanged: {:?}", default_user_name_changed);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "MaintenanceHistoryDays" => {
                maintenance_history_days = decode_i64(reader, name, attributes)? as u32;
                println!("MaintenanceHistoryDays: {:?}", maintenance_history_days);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "MasterKeyChanged" => {
                master_key_changed = decode_optional_datetime(reader, name, attributes)?;
                println!("MasterKeyChanged: {:?}", master_key_changed);
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
                memory_protection = MemoryProtection::parse(reader, name, attributes)?;
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
              if name.local_name == "SettingsChanged" => {
                settings_changed = decode_optional_datetime(reader, name, attributes)?;
                println!("SettingsChanged: {:?}", settings_changed);
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

fn decode_history<R: Read>(reader: &mut EventReader<R>) -> Result<Vec<Entry>, String> {
    let mut elements = vec![];
    elements.push(::xml::name::OwnedName::local("History"));

    let mut entries = Vec::<Entry>::new();
    while elements.len() > 0 {
        let event = reader.next().map_err(|_|"")?;
        println!("Decode history...");
        match event {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::StartElement { name, attributes: _, .. }
              if name.local_name == "Entry" => {
                let entry = decode_entry(reader)?; //, name, attributes)?;
                println!("Entry: {:?}", entry);
                entries.push(entry);
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
    Ok(entries)
}

fn decode_entry<R: Read>(reader: &mut EventReader<R>) -> Result<Entry, String> {
    let mut elements = vec![];
    elements.push(::xml::name::OwnedName::local("Entry"));

    let mut history = Vec::new();
    while elements.len() > 0 {
        let event = reader.next().map_err(|_|"")?;
        println!("Decode entry...");
        match event {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::StartElement { name, attributes: _, .. }
              if name.local_name == "History" => {
                history = decode_history(reader)?; //, name, attributes)?;
                println!("History: {:?}", history);
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
    Ok(Entry {
        history,
        ..Entry::default()
    })
}

fn decode_times<R: Read>(reader: &mut EventReader<R>) -> Result<Times, String> {
    let mut elements = vec![];
    elements.push(::xml::name::OwnedName::local("Times"));

    let default_date = DateTime::parse_from_rfc3339("1970-01-01T00:00:00+00:00").unwrap().with_timezone(&Utc);
    let mut times = Times {
        creation_time: default_date,
        last_access_time: default_date,
        last_modification_time: default_date,
        location_changed: default_date,
        expiry_time: default_date,
        expires: false,
        usage_count: 0,
    };
    while elements.len() > 0 {
        let event = reader.next().map_err(|_|"")?;
        println!("Decode times...");
        match event {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "CreationTime" => {
                times.creation_time = DateTime::from(decode_datetime(reader, name, attributes)?);
                println!("CreationTime: {:?}", times.creation_time);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "LastAccessTime" => {
                times.last_access_time = DateTime::from(decode_datetime(reader, name, attributes)?);
                println!("LastAccessTime: {:?}", times.last_access_time);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "LastModificationTime" => {
                times.last_modification_time = DateTime::from(decode_datetime(reader, name, attributes)?);
                println!("LastModificationTime: {:?}", times.last_modification_time);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "ExpiryTime" => {
                times.expiry_time = DateTime::from(decode_datetime(reader, name, attributes)?);
                println!("ExpiryTime: {:?}", times.expiry_time);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "LocationChanged" => {
                times.location_changed = DateTime::from(decode_datetime(reader, name, attributes)?);
                println!("LocationChanged: {:?}", times.location_changed);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "Expires" => {
                times.expires = decode_bool(reader, name, attributes)?;
                println!("Expires: {:?}", times.expires);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "UsageCount" => {
                times.usage_count = decode_i64(reader, name, attributes)? as i32;
                println!("UsageCount: {:?}", times.usage_count);
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

    Ok(times)
}

fn decode_group<R: Read>(reader: &mut EventReader<R>) -> Result<Group, String> {
    let mut elements = vec![];
    elements.push(::xml::name::OwnedName::local("Group"));

    let mut uuid = Uuid::default();
    let mut group_name = "".to_string();
    let mut notes = "".to_string();
    let mut icon_id = 0;
    let default_date = DateTime::parse_from_rfc3339("1970-01-01T00:00:00+00:00").unwrap().with_timezone(&Utc);
    let mut times = Times {
        creation_time: default_date,
        last_access_time: default_date,
        last_modification_time: default_date,
        location_changed: default_date,
        expiry_time: default_date,
        expires: false,
        usage_count: 0,
    };
    let mut is_expanded = false;
    let mut last_top_visible_entry = Uuid::default();
    let mut entries = Vec::<Entry>::new();
    let mut groups = Vec::<Group>::new();
    while elements.len() > 0 {
        let event = reader.next().map_err(|_|"")?;
        println!("Decode group...");
        match event {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "UUID" => {
                uuid = decode_uuid(reader, name, attributes)?;
                println!("UUID: {:?}", uuid);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "Name" => {
                group_name = decode_string(reader, name, attributes)?;
                println!("Name: {:?}", group_name);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "Notes" => {
                notes = decode_string(reader, name, attributes)?;
                println!("Notes: {:?}", notes);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "IconID" => {
                icon_id = decode_i64(reader, name, attributes)?;
                println!("IconID: {:?}", icon_id);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "Times" => {
                times = Times::parse(reader, name, attributes)?;
                println!("Times: {:?}", times);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "IsExpanded" => {
                is_expanded = decode_bool(reader, name, attributes)?;
                println!("IsExpanded: {:?}", is_expanded);
            },
            XmlEvent::StartElement { name, attributes, .. } if name.local_name == "LastTopVisibleEntry" => {
                last_top_visible_entry = decode_uuid(reader, name, attributes)?;
                println!("LastTopVisibleEntry: {:?}", last_top_visible_entry);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "Entry" => {
                let entry = Entry::parse(reader, name, attributes)?;
                println!("Entry: {:?}", entry);
                entries.push(entry);
            },
            XmlEvent::StartElement { name, attributes, .. }
              if name.local_name == "Group" => {
                let group = Group::parse(reader, name, attributes)?;
                println!("Group: {:?}", group);
                groups.push(group);
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

    Ok(Group {
        uuid,
        name: group_name,
        notes,
        icon_id: icon_id as u32,
        times,
        is_expanded,
        //<DefaultAutoTypeSequence/>
        //_enable_auto_type: "".to_string(),
        //_enable_searching: "".to_string(),
        last_top_visible_entry,
        //custom_data: CustomData,
        group: groups,
        entry: entries,
    })
}

fn decode_root<R: Read>(reader: &mut EventReader<R>) -> Result<Vec<Group>, String> {
    //let mut elements: Vec<::xml::name::OwnedName> = vec![];
    //elements.push("Foo".into());
    let mut elements = vec![];
    elements.push(::xml::name::OwnedName::local("Root"));
    //let mut elements: Vec<::xml::name::OwnedName> = vec![];
    //elements.push(::xml::name::Name::from("Foo").to_owned());
    //elements.push(::xml::name::Name::from("Foo").into());
    //let mut elements = vec![];
    //elements.push(::xml::name::OwnedName::from_str("Foo").unwrap());

    let mut groups = Vec::<Group>::new();
    while elements.len() > 0 {
        let event = reader.next().map_err(|_|"")?;
        println!("Decode root...");
        match event {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document".to_string());
            },
            XmlEvent::StartElement { name, attributes: _, .. }
              if name.local_name == "Group" => {
                let group = decode_group(reader)?; //, name, attributes)?;
                println!("Group: {:?}", group);
                groups.push(group);
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
    Ok(groups)
}

//fn consume_element<R: Read>(reader: &mut yaserde::de::Deserializer<R>, mut event: XmlEvent) -> Result<(), String> {
fn decode_document_old<R: Read>(mut reader: &mut EventReader<R>) -> Result<KeePassFile, String> {
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
    let mut root = Vec::<Group>::default();

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
                meta = decode_meta_old(&mut reader)?;
                println!("Meta: {:?}", meta);
            },
            XmlEvent::StartElement { name, .. } if name.local_name == "Root" => {
                root = decode_root(&mut reader)?;
                println!("Root: {:?}", root);
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
            return Ok(KeePassFile { meta, root });
            //return Ok(KeePassFile { meta, ..KeePassFile::default() });
        }
        event = reader.next().map_err(|_|"")?;
    }
}

const KDBX_MAGIC: u32 = 0x9AA2D903;

const KDBX1_MAGIC_TYPE: u32 = 0xB54BFB65;
const KDBX2_BETA_MAGIC_TYPE: u32 = 0xB54BFB66;
const KDBX2_MAGIC_TYPE: u32 = 0xB54BFB67;

fn save_file() -> io::Result<()> {
    let mut file = File::create("data-out.kbdx")?;
    let major_version = 4;
    let minor_version = 0;
    let mut header = vec![];
    header.write_u32::<LittleEndian>(KDBX_MAGIC)?;
    header.write_u32::<LittleEndian>(KDBX2_MAGIC_TYPE)?;
    header.write_u16::<LittleEndian>(minor_version)?;
    header.write_u16::<LittleEndian>(major_version)?;
    let mut key = Key::new();
    key.set_user_password("asdf");
    let composite_key = key.composite_key();
    let kdf = AesKdf::default();
    let mut custom_data = HashMap::new();
    custom_data.insert(KDF_PARAM_UUID.to_string(), MapValue::ByteArray(KDF_AES_KDBX3.into_bytes().to_vec()));
    kdf.save(&mut custom_data);
    let transform_key = kdf.transform_key(&composite_key).expect("Failed to transform key");
    let master_seed = [0u8; 32];
    let iv = [0u8; 16];
    let mut tlvs = BTreeMap::new();
    tlvs.insert(TlvType::MasterSeed.to_u8().unwrap(), vec![master_seed.to_vec()]);
    tlvs.insert(TlvType::CipherId.to_u8().unwrap(), vec![CIPHER_ID_AES256_CBC.into_bytes().to_vec()]);
    tlvs.insert(TlvType::EncryptionIv.to_u8().unwrap(), vec![iv.to_vec()]);
    tlvs.insert(TlvType::CompressionFlags.to_u8().unwrap(), vec![Compression::None.to_u32().unwrap().to_le_bytes().to_vec()]);
    tlvs.insert(TlvType::KdfParameters.to_u8().unwrap(), vec![save_map(&custom_data)]);
    header.append(&mut save_tlvs(&mut io::sink(), &tlvs, major_version).unwrap());
    file.write(&header)?;
    let mut context = Context::new(&SHA256);
    context.update(&header);
    let digest = context.finish();
    file.write(digest.as_ref())?;
    // header.append(&mut digest.as_ref().to_owned());

    let mut master_key = master_seed.to_vec();
    master_key.extend(transform_key);
    let mut context = Context::new(&SHA256);
    let mut hmac_context = Context::new(&SHA512);
    context.update(&master_key);
    hmac_context.update(&master_key);
    hmac_context.update(&[1u8]);
    master_key = context.finish().as_ref().to_owned();
    let hmac_key_base = hmac_context.finish().as_ref().to_owned();

    let mut hmac_context = Context::new(&SHA512);
    hmac_context.update(&[0xff; 8]);
    hmac_context.update(&hmac_key_base);
    let hmac_key = hmac_context.finish().as_ref().to_owned();

    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key);
    let hmac_tag = hmac::sign(&hmac_key, &header);
    file.write(hmac_tag.as_ref())?;

    let output = BlockWriter::new(&hmac_key_base, file);
    let cipher = Cipher::aes_256_cbc();
    let mut output = Crypto::new(cipher, &master_key, Some(&iv), output).unwrap();

    let stream_cipher = 2u32;
    let stream_key = [0u8; 32];
    let mut inner_tlvs = BTreeMap::new();
    inner_tlvs.insert(1, vec![stream_cipher.to_le_bytes().to_vec()]);
    inner_tlvs.insert(2, vec![stream_key.to_vec()]);
    save_tlvs(&mut output, &inner_tlvs, major_version).unwrap();
    output.flush()?;
    drop(output);

    Ok(())
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

    if magic != KDBX_MAGIC {
        let _ = writeln!(stderr, "Invalid database file\n");
        process::exit(1);
    }

    let mut custom_data = HashMap::<String, Vec<u8>>::new();

    match magic_type {
        KDBX1_MAGIC_TYPE => {
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
        // KDBX2_BETA_MAGIC_TYPE => {
        //     // XXX Untested
        //     let _ = writeln!(stderr, "KeePass 2.x Beta files not supported\n");
        //     process::exit(1);
        // },
        KDBX2_MAGIC_TYPE | KDBX2_BETA_MAGIC_TYPE => {
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
            unsafe { KDBX4 = false; };
            custom_data.insert(KDF_PARAM_UUID.to_string(), KDF_AES_KDBX3.as_bytes().to_vec());
        },
        4 => {
        },
        1 => {
            custom_data.insert(KDF_PARAM_UUID.to_string(), KDF_AES_KDBX3.as_bytes().to_vec());
        },
        _ => {
            let _ = writeln!(stderr,
                     "Unsupported KeePass 2.x database version ({}.{})\n",
                     major_version, minor_version);
            process::exit(1);
        },
    };
    let mut tlvs = HashMap::new();
    let mut inner_tlvs = HashMap::new();
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
            8 => { inner_tlvs.insert(2u8, tlv_data); },
            10 => { inner_tlvs.insert(1u8, tlv_data); },
            11 => {
                tlvs.insert(tlv_type, tlv_data.clone());
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
    let cipher_id = Uuid::from_slice(&tlvs[&2u8]).unwrap();
    println!("D: {:?}", cipher_id);
    if cipher_id != CIPHER_ID_AES256_CBC {
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
            // let _ = writeln!(stderr, "Unsupported no compressed file\n");
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

    let kdf_id = Uuid::from_slice(&custom_data[KDF_PARAM_UUID]).unwrap();
    println!("KDF: {:?}", kdf_id);

    let transform_key = match kdf_id {
        x if x == KDF_AES_KDBX3 => {
            let custom_data = load_map(&tlvs[&11]).unwrap();
            //unimplemented!("KDBX 3 AES-KDF not supported!");
            AesKdf::load(&custom_data)?.transform_key(&composite_key)?
            // transform_aes_kdf(&composite_key, &custom_data)?
        },
        x if x == KDF_AES_KDBX4 => {
            unimplemented!("KDBX 4 AES-KDF not supported!");
        },
        x if x == KDF_ARGON2_D => {
            transform_argon2(&composite_key, &custom_data)?
            //unimplemented!("Argon2 KDF not supported!");
        },
        _ => {
            unimplemented!("Unknown");
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

    let contents = if major_version == 4 {
        let mut ciphertext = vec![];
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
            println!("Complete");
            ciphertext.extend(block);
        }

        let data = decrypt(Cipher::aes_256_cbc(), &master_key, Some(encryption_iv), &ciphertext).unwrap();
        let mut gz = GzDecoder::new(Cursor::new(data));

        loop {
            let tlv_type = gz.read_u8()?;
            let tlv_len = gz.read_u32::<LittleEndian>()?;
            let mut tlv_data = vec![0; tlv_len as usize];
            gz.read_exact(&mut tlv_data)?;
            if tlv_type == 0 {
                break;
            }
            debug!("TLV({}, {}): {:?}", tlv_type, tlv_len, tlv_data);
            inner_tlvs.insert(tlv_type, tlv_data);
        };

        let mut contents = String::new();
        gz.read_to_string(&mut contents)?;
        contents
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
        contents
    };

    enum CipherType {
        Salsa20(Salsa20),
        ChaCha20(ChaCha20),
    }

    impl CipherType {
        fn apply_keystream(&mut self, buf: &mut [u8]) {
            match self {
                Self::Salsa20(c) => c.apply_keystream(buf),
                Self::ChaCha20(c) => c.apply_keystream(buf),
            }
        }
    }

    let mut cipher_opt = None;
    let mut xml_file = File::create("data.xml")?;
    let _ = xml_file.write(&contents.as_bytes());
    const KDBX4_TIME_OFFSET : i64 = 62135596800;
    let package = parser::parse(&contents).unwrap();
    let document = package.as_document();
    println!("Root element: {}", document.root().children()[0].element().unwrap().name().local_part());
    let database_name_node = evaluate_xpath(&document, "/KeePassFile/Meta/DatabaseName/text()").expect("Missing database name");
    println!("Database Name: {}", database_name_node.string());
    let database_name_changed_node = evaluate_xpath(&document, "/KeePassFile/Meta/DatabaseNameChanged/text()").expect("Missing database name changed");
    let datetime: DateTime<Local> = if major_version == 3 {
        DateTime::parse_from_rfc3339(&database_name_changed_node.string()).expect("failed to parse timestamp").with_timezone(&Local)
    } else {
        let timestamp = Cursor::new(decode(&database_name_changed_node.string()).expect("Valid base64")).read_i64::<LittleEndian>()? - KDBX4_TIME_OFFSET;
        //let naive = NaiveDateTime::from_timestamp(timestamp, 0);
        //let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
        Local.timestamp(timestamp, 0)
    };
    println!("Database Name Changed: {}", datetime.format("%Y-%m-%d %l:%M:%S %p %Z"));

    let xpath_context = XPathContext::new();
    let protected_nodes = evaluate_xpath(&document, "//Value[@Protected = 'True']/text()").expect("Missing database entries");
    let xpath_current = Factory::new().build(".").expect("Failed to compile XPath").expect("Empty XPath expression");
    match protected_nodes {
        Value::Nodeset(nodes) => {
            for entry in nodes.document_order() {
                let p = xpath_current.evaluate(&xpath_context, entry).expect("Missing entry text");
                println!("P: {:?}, ('{}')", p, p.string());
                let inner_stream_cipher = &inner_tlvs[&1u8];
                if inner_stream_cipher.len() != 4 { panic!("Invalid inner cipher"); }
                let inner_cipher = u32::from_le_bytes(inner_stream_cipher[..].try_into().unwrap());
                println!("Inner Cipher: {inner_cipher}");
                assert!(inner_cipher == 2 || inner_cipher == 3); // Salsa20 or ChaCha20
                let mut p_ciphertext = decode(&p.string()).expect("Valid base64");
                //let p_algo = unmake_u32(&inner_tlvs[&0x01u8]).unwrap();
                //assert_eq!(p_algo, 3);
                let p_key = &inner_tlvs[&0x02u8];
                println!("p_key: {}", p_key.len());
                if cipher_opt.is_none() {
                    let cipher = if inner_cipher == 2 {
                        //let nonce = Vec::from_hex("E830094B97205D2A").unwrap();
                        let nonce = hex!("E830094B97205D2A");
                        let mut p_context = Context::new(&SHA256);
                        p_context.update(p_key);
                        let p2_key = p_context.finish().as_ref().to_owned();
                        let key = Salsa20_Key::from_slice(&p2_key[0..32]);
                        CipherType::Salsa20(Salsa20::new(&key, &nonce.into()))
                    } else {
                        let mut p_context = Context::new(&SHA512);
                        p_context.update(p_key);
                        let p2_key = p_context.finish().as_ref().to_owned();
                        println!("p2_key: {}", p2_key.len());
                        let key = GenericArray::from_slice(&p2_key[0..32]);
                        let nonce = GenericArray::from_slice(&p2_key[32..32+12]);
                        CipherType::ChaCha20(ChaCha20::new(&key, &nonce))
                    };
                    cipher_opt = Some(cipher);
                }
                let cipher = cipher_opt.as_mut().unwrap();
                println!("Protected Value Ciphertext: {:?}", p_ciphertext);
                cipher.apply_keystream(&mut p_ciphertext);
                //let data = decrypt(Cipher::chacha20(), &p2_key[0..32], Some(&p2_key[32..32+12]), &p_ciphertext).unwrap();
                let value = String::from_utf8(p_ciphertext).unwrap_or("«Failed to decrypt value»".to_owned());
                println!("Protected Value: {:?}", &value);
                match entry {
                    sxd_xpath::nodeset::Node::Text(t) => {
                        t.set_text(&value);
                    },
                    _ => {},
                }
            }
        },
        _ => { panic!("XML corruption"); },
    }
    let xpath_username = Factory::new().build("String[Key/text() = 'UserName']/Value/text()").expect("Failed to compile XPath").expect("Empty XPath expression");
    let xpath_last_mod_time = Factory::new().build("Times/LastModificationTime/text()").expect("Failed to compile XPath").expect("Empty XPath expression");
    let xpath_password = Factory::new().build("String[Key/text() = 'Password']/Value[@Protected = 'True']/text()").expect("Failed to compile XPath").expect("Empty XPath expression");
    //let entry_nodes = evaluate_xpath(&document, "/KeePassFile/Root/Group/Entry").expect("Missing database entries");
    let entry_nodes = evaluate_xpath(&document, "//Entry").expect("Missing database entries");
    match entry_nodes {
        Value::Nodeset(nodes) => {
            for entry in nodes.document_order() {
                //let n = evaluate_xpath(&document, "/KeePassFile/Root/Group/Entry/String[Key/text() = 'UserName']/Value/text()").expect("Missing entry username");
                let n = xpath_username.evaluate(&xpath_context, entry).expect("Missing entry username");
                let t = xpath_last_mod_time.evaluate(&xpath_context, entry).expect("Missing entry modification");
                let p = xpath_password.evaluate(&xpath_context, entry).expect("Missing entry password");
                println!("Name: {}", n.string());
                let datetime: DateTime<Local> = if major_version == 3 {
                    DateTime::parse_from_rfc3339(&database_name_changed_node.string()).expect("failed to parse timestamp").with_timezone(&Local)
                } else {
                    let timestamp = Cursor::new(decode(&t.string()).expect("Valid base64")).read_i64::<LittleEndian>()? - KDBX4_TIME_OFFSET;
                    Local.timestamp(timestamp, 0)
                };
                println!("Changed: {}", datetime.format("%Y-%m-%d %l:%M:%S %p %Z"));
                println!("Password: {:?}", p.string());
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
            XmlEvent::StartElement { name, attributes, .. } => { crate::KeePassFile::parse(&mut reader, name, attributes).map_err(|x| ::std::io::Error::new(::std::io::ErrorKind::Other, x))?; },
            XmlEvent::EndDocument => { println!("End"); break; },
            _ => {},
        }
    }

    save_file().unwrap();

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
                                XmlEvent::StartElement { name, .. }
                                  if name.local_name == "LastModificationTime" => {
                                    loop {
                                        match reader.next_event()? {
                                            XmlEvent::Characters(_k) => {
                                                //value = k;
                                            },
                                            XmlEvent::EndElement { name }
                                              if name.local_name == "LastModificationTime" => {
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
    println!("Done!");

    Ok(())
}
