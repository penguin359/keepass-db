//! Read, modify and write KeePass 2.x databases

use std::collections::VecDeque;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::slice::Iter;
use std::fs::File;
use std::io::prelude::*;
use std::io::Cursor;
use std::io::{self, SeekFrom};
use std::process;
//use std::cell::RefCell;
//use std::rc::Rc;
use std::cmp;

use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};

use log::debug;

//use hex::ToHex;
// use hex::FromHex;
use base64::{decode, encode};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use hex_literal::hex;
use openssl::error::ErrorStack;
use uuid::{uuid, Uuid};
//use borsh::de::BorshDeserialize;  // try_from_slice()
// use chacha20::stream_cipher::generic_array::GenericArray;
// use chacha20::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use chacha20::ChaCha20;
use generic_array::GenericArray;
use chrono::prelude::*;
use flate2::read::GzDecoder;
use openssl::symm::{decrypt, encrypt, Cipher, Crypter, Mode};
use ring::digest::{Context, SHA256, SHA512};
use ring::hmac;
use salsa20::cipher::{KeyIvInit, StreamCipher};
use salsa20::Key as Salsa20_Key;
use salsa20::Salsa20;
use sxd_document::parser;
use sxd_xpath::{evaluate_xpath, Context as XPathContext, Factory, Value};

use xml::attribute::OwnedAttribute;
use xml::name::OwnedName;
use xml::reader::{EventReader, ParserConfig, XmlEvent};
use xml::writer::EventWriter;
use derive_getters::Getters;

use keepass_db_derive::{KdbxParse, KdbxSerialize};

mod kdb1;
mod utils;
pub mod protected_stream;


//trait KdbxDefault: Default {
//    fn provide_default() -> Self
//        {
//        <Self as Default>::default()
//    }
//}

trait KdbxParse<C>: Sized + Default {
    //    fn provide_default() -> Self
    //        where Self: Default {
    //        <Self as Default>::default()
    //    }

    fn parse<R: Read>(
        reader: &mut EventReader<R>,
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
        context: &mut C,
    ) -> Result<Option<Self>, String>;
}

//impl<T: KdbxParse> KdbxParse
//    where T: KdbxParse + Default {
//    fn default() -> Self {

trait KdbxSerialize<C>: Sized {
    fn serialize2<W: Write>(
        writer: &mut EventWriter<W>,
        value: Self,
        context: &mut C,
    ) -> Result<(), String>;
}

#[cfg(test)]
mod tests;

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
fn load_tlvs<R: Read>(
    input: &mut R,
    major_version: u16,
) -> io::Result<(BTreeMap<u8, Vec<Vec<u8>>>, Vec<u8>)> {
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
    }
    Ok((tlvs, header_blob))
}

fn save_tlvs<W: Write>(
    output: &mut W,
    tlvs: &BTreeMap<u8, Vec<Vec<u8>>>,
    major_version: u16,
) -> io::Result<Vec<u8>> {
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
    output.write(&bytes)?;
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
pub enum MapValue {
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

fn load_map(tlv_data: &[u8]) -> io::Result<HashMap<String, MapValue>> {
    let mut custom_data = HashMap::new();
    let kdf_parameters = &tlv_data;
    let mut c = Cursor::new(kdf_parameters);
    let variant_minor = c.read_u8()?;
    let variant_major = c.read_u8()?;
    if variant_major != 1 {
        let _ = eprintln!(
            "Unsupported variant dictionary version ({}.{})\n",
            variant_major, variant_minor
        );
        return Err(io::Error::new(io::ErrorKind::Other, "Unsupported variant"));
    };

    loop {
        let item_type = MapType::from_u8(c.read_u8()?)
            .ok_or(io::Error::new(io::ErrorKind::Other, "Unknown type"))?;
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
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Invalid bool value",
                    ));
                }
                MapValue::Bool(item_value[0] != 0)
            }
            MapType::Int32 => {
                MapValue::Int32(i32::from_le_bytes(item_value.try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::Unsupported, "Invalid i32 value")
                })?))
            }
            MapType::Int64 => {
                MapValue::Int64(i64::from_le_bytes(item_value.try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::Unsupported, "Invalid i64 value")
                })?))
            }
            MapType::UInt32 => {
                MapValue::UInt32(u32::from_le_bytes(item_value.try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::Unsupported, "Invalid u32 value")
                })?))
            }
            MapType::UInt64 => {
                MapValue::UInt64(u64::from_le_bytes(item_value.try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::Unsupported, "Invalid u64 value")
                })?))
            }
            MapType::String => {
                MapValue::String(String::from_utf8(item_value).map_err(|_| {
                    io::Error::new(io::ErrorKind::Unsupported, "Invalid string value")
                })?)
            }
            MapType::ByteArray => MapValue::ByteArray(item_value),
            MapType::None => {
                unreachable!()
            }
        };
        custom_data.insert(item_key_str.to_owned().to_string(), item_value);
    }
    Ok(custom_data)
}

fn save_map(map: &HashMap<String, MapValue>) -> Vec<u8> {
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
            }
            MapValue::Int32(v) => v.to_le_bytes().to_vec(),
            MapValue::Int64(v) => v.to_le_bytes().to_vec(),
            MapValue::UInt32(v) => v.to_le_bytes().to_vec(),
            MapValue::UInt64(v) => v.to_le_bytes().to_vec(),
            MapValue::String(v) => v.as_bytes().to_vec(),
            MapValue::ByteArray(v) => v.clone(),
        };
        output
            .write_u32::<LittleEndian>(item_value.len() as u32)
            .unwrap();
        output.write(&item_value).unwrap();
    }
    output.write_u8(0).unwrap(); // End of dictionary
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

impl<R: Read> BlockReader<R> {
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
        //             eprintln!("Possible header corruption\n");
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
            return Ok(0);
        } else if self.buf.len() == 0 {
            self.load_next_block()?;
        }
        let mut index = 0;
        if index >= buf.len() {
            return Ok(index);
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

impl<W: Write> BlockWriter<W> {
    const DEFAULT_BLOCK_SIZE: u32 = 1024 * 1024;

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
        self.output
            .write_u32::<LittleEndian>(self.buf.len() as u32)?;
        self.output.write(&self.buf)?;
        self.buf.truncate(0);
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = cmp::min(
            self.block_size as usize - cmp::min(self.buf.len(), self.block_size as usize),
            buf.len(),
        );
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
    _error: ErrorStack,
}

impl From<ErrorStack> for CryptoError {
    fn from(error: ErrorStack) -> Self {
        Self { _error: error }
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
        self.output.flush().unwrap();
        // let rest = self
        //     .crypter
        //     .finalize(&mut self.buf)
        //     .expect("Failed to finalize encryption");
        // self.output
        //     .write_all(&self.buf[..rest])
        //     .expect("Failed to flush");
    }
}

impl<W: Write> Write for Crypto<W> {
    fn flush(&mut self) -> io::Result<()> {
        self.buf = vec![0; self.block_size];
        let rest = self
            .crypter
            .finalize(&mut self.buf)
            .expect("Failed to finalize encryption");
        self.output
            .write_all(&self.buf[..rest])
            .expect("Failed to flush");
        self.buf = vec![];
        self.output.flush()?;
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

pub struct Key {
    user_password: Option<Vec<u8>>,
    keyfile: Option<Vec<u8>>,
    windows_credentials: Option<Vec<u8>>,
}

impl Key {
    pub fn new() -> Key {
        Key {
            user_password: None,
            keyfile: None,
            windows_credentials: None,
        }
    }

    pub fn set_user_password<T>(&mut self, user_password: T)
    where
        T: AsRef<[u8]>,
    {
        let mut context = Context::new(&SHA256);
        context.update(user_password.as_ref());
        self.user_password = Some(context.finish().as_ref().to_owned());
    }

    /* TODO Use this function */
    pub fn set_keyfile<T>(&mut self, keyfile: T)
    where
        T: AsRef<[u8]>,
    {
        let mut context = Context::new(&SHA256);
        context.update(keyfile.as_ref());
        self.keyfile = Some(context.finish().as_ref().to_owned());
    }

    /* TODO Use this function */
    fn _set_windows_credentials<T>(&mut self, windows_credentials: T)
    where
        T: AsRef<[u8]>,
    {
        let mut context = Context::new(&SHA256);
        context.update(windows_credentials.as_ref());
        self.windows_credentials = Some(context.finish().as_ref().to_owned());
    }

    pub fn composite_key(&self) -> Vec<u8> {
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

mod kdf;
pub use kdf::*;

pub const KDF_AES_KDBX3: Uuid = uuid!("c9d9f39a-628a-4460-bf74-0d08c18a4fea");
const KDF_AES_KDBX4: Uuid = uuid!("7c02bb82-79a7-4ac0-927d-114a00648238");
const KDF_ARGON2_D: Uuid = uuid!("ef636ddf-8c29-444b-91f7-a9a403e30a0c");
const _KDF_ARGON2_ID: Uuid = uuid!("9e298b19-56db-4773-b23d-fc3ec6f0a1e6");

const _CIPHER_ID_AES128_CBC: Uuid = uuid!("61ab05a1-9464-41c3-8d74-3a563df8dd35");
const CIPHER_ID_AES256_CBC: Uuid = uuid!("31c1f2e6-bf71-4350-be58-05216afc5aff");
const _CIPHER_ID_TWOFISH_CBC: Uuid = uuid!("ad68f29f-576f-4bb9-a36a-d47af965346c");
const _CIPHER_ID_CHACHA20: Uuid = uuid!("d6038a2b-8b6f-4cb5-a524-339a31dbb59a");

fn consume_element<R: Read>(
    reader: &mut EventReader<R>,
    name: OwnedName,
    _attributes: Vec<OwnedAttribute>,
) -> Result<Option<String>, String> {
    let mut elements = vec![];
    println!("A tag: {}", &name);
    elements.push(name);

    let mut string = None;

    let mut event = reader
        .next()
        .map_err(|_| "Failed to retrieve next XML event")?;
    loop {
        match event {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document, start of document".to_string());
            }
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document, end of document".to_string());
            }
            XmlEvent::StartElement { name, .. } => {
                elements.push(name);
            }
            XmlEvent::Characters(k) => {
                string = Some(k);
            }
            XmlEvent::EndElement { name, .. } => {
                let start_tag = elements.pop().expect("Can't consume a bare end element");
                if start_tag != name {
                    return Err(format!(
                        "Start tag <{}> mismatches end tag </{}>",
                        start_tag, name
                    ));
                }
            }
            _ => {
                // Consume any PI, text, comment, or cdata node
                //return Ok(());
            }
        };
        if elements.len() == 0 {
            return Ok(string);
        }
        event = reader
            .next()
            .map_err(|_| "Failed to retrieve next XML event")?;
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
        match reader
            .next()
            .map_err(|_| "Failed to retrieve next XML event")?
        {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document".to_string());
            }
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document".to_string());
            }
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                return Ok(ElementEvent::StartElement { name, attributes });
            }
            XmlEvent::Characters(_) => {}
            XmlEvent::CData(_) => {}
            XmlEvent::Whitespace(_) => {}
            XmlEvent::ProcessingInstruction { .. } => {}
            XmlEvent::EndElement { name, .. } => {
                return Ok(ElementEvent::EndElement { name });
            }
            _ => {
                // Consume any PI, text, comment, or cdata node
                //return Ok(());
            }
        };
    }
}

fn decode_optional_string<R: Read>(
    reader: &mut EventReader<R>,
    name: OwnedName,
    _attributes: Vec<OwnedAttribute>,
) -> Result<Option<String>, String> {
    let mut elements = vec![];
    elements.push(name);

    let mut string = String::new();

    let mut event = reader
        .next()
        .map_err(|_| "Failed to retrieve next XML event")?;
    loop {
        match event {
            XmlEvent::StartDocument { .. } => {
                return Err("Malformed XML document".to_string());
            }
            XmlEvent::EndDocument { .. } => {
                return Err("Malformed XML document".to_string());
            }
            XmlEvent::StartElement { name, .. } => {
                elements.push(name);
            }
            XmlEvent::Characters(k) => {
                if elements.len() == 1 {
                    string.push_str(&k);
                }
            }
            XmlEvent::Whitespace(k) => {
                if elements.len() == 1 {
                    string.push_str(&k);
                }
            }
            XmlEvent::CData(k) => {
                if elements.len() == 1 {
                    string.push_str(&k);
                }
            }
            XmlEvent::EndElement { name, .. } => {
                let start_tag = elements.pop().expect("Can't consume a bare end element");
                if start_tag != name {
                    return Err(format!(
                        "Start tag <{}> mismatches end tag </{}>",
                        start_tag, name
                    ));
                }
            }
            _ => {
                // Consume any PI, text, comment, or cdata node
                //return Ok(());
            }
        };
        if elements.len() == 0 {
            if string.len() == 0 {
                return Ok(None);
            } else {
                return Ok(Some(string));
            }
        }
        event = reader.next().map_err(|_| "")?;
    }
}

fn encode_optional_string<W: Write>(
    writer: &mut EventWriter<W>,
    value: Option<&str>,
) -> Result<(), String> {
    if let Some(contents) = value {
        writer
            .write(xml::writer::XmlEvent::characters(contents))
            .map_err(|_| "".to_string())
    } else {
        Ok(())
    }
}

fn decode_string<R: Read>(
    reader: &mut EventReader<R>,
    name: OwnedName,
    attributes: Vec<OwnedAttribute>,
) -> Result<String, String> {
    decode_optional_string(reader, name, attributes).map(|x| x.unwrap_or_else(|| "".into()))
}

impl<C> KdbxParse<C> for String {
    fn parse<R: Read>(
        reader: &mut EventReader<R>,
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
        _context: &mut C,
    ) -> Result<Option<Self>, String> {
        decode_optional_string(reader, name, attributes)
    }
}

fn encode_string<W: Write>(writer: &mut EventWriter<W>, value: &str) -> Result<(), String> {
    encode_optional_string(writer, Some(value))
}

impl<C> KdbxSerialize<C> for String {
    fn serialize2<W: Write>(
        writer: &mut EventWriter<W>,
        value: Self,
        _context: &mut C,
    ) -> Result<(), String> {
        encode_string(writer, &value)
    }
}

fn decode_optional_base64<R: Read>(
    reader: &mut EventReader<R>,
    name: OwnedName,
    attributes: Vec<OwnedAttribute>,
) -> Result<Option<Vec<u8>>, String> {
    Ok(decode_optional_string(reader, name, attributes)?
        .map(|x| decode(&x).unwrap() /* .as_bytes().into() */))
}

fn encode_optional_base64<W: Write, T: AsRef<[u8]>>(
    writer: &mut EventWriter<W>,
    value: Option<T>,
) -> Result<(), String> {
    // let bytes = value.map(|x| encode(x.as_ref()));
    // encode_optional_string(writer, bytes.map(|x| x.as_str()))
    encode_optional_string(writer, value.map(|x| encode(x.as_ref())).as_deref())
}

fn decode_base64<R: Read>(
    reader: &mut EventReader<R>,
    name: OwnedName,
    attributes: Vec<OwnedAttribute>,
) -> Result<Vec<u8>, String> {
    Ok(decode_optional_base64(reader, name, attributes)?.unwrap_or_default())
}

fn encode_base64<W: Write, T: AsRef<[u8]>>(
    writer: &mut EventWriter<W>,
    value: T,
) -> Result<(), String> {
    encode_optional_base64(writer, Some(value))
}

fn decode_optional_bool<R: Read>(
    reader: &mut EventReader<R>,
    name: OwnedName,
    attributes: Vec<OwnedAttribute>,
) -> Result<Option<bool>, String> {
    decode_optional_string(reader, name, attributes)
        .map(|x| x.map(|y| y.eq_ignore_ascii_case("true")))
}

fn encode_optional_bool<W: Write>(
    writer: &mut EventWriter<W>,
    value: Option<bool>,
) -> Result<(), String> {
    encode_optional_string(writer, value.map(|x| if x { "True" } else { "False" }))
}

// fn decode_bool<R: Read>(
//     reader: &mut EventReader<R>,
//     name: OwnedName,
//     attributes: Vec<OwnedAttribute>,
// ) -> Result<bool, String> {
//     decode_optional_bool(reader, name, attributes).map(|x| x.unwrap_or(false))
// }

impl<C> KdbxParse<C> for bool {
    fn parse<R: Read>(
        reader: &mut EventReader<R>,
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
        _context: &mut C,
    ) -> Result<Option<Self>, String> {
        decode_optional_bool(reader, name, attributes)
    }
}

fn encode_bool<W: Write>(writer: &mut EventWriter<W>, value: bool) -> Result<(), String> {
    encode_optional_bool(writer, Some(value))
}

impl<C> KdbxSerialize<C> for bool {
    fn serialize2<W: Write>(
        writer: &mut EventWriter<W>,
        value: Self,
        _context: &mut C,
    ) -> Result<(), String> {
        encode_bool(writer, value)
    }
}

fn decode_optional_i64<R: Read>(
    reader: &mut EventReader<R>,
    name: OwnedName,
    attributes: Vec<OwnedAttribute>,
) -> Result<Option<i64>, String> {
    decode_optional_string(reader, name, attributes).map(|x| x.map(|y| y.parse().unwrap_or(0)))
}

fn encode_optional_i64<W: Write>(
    writer: &mut EventWriter<W>,
    value: Option<i64>,
) -> Result<(), String> {
    encode_optional_string(writer, value.map(|x| format!("{}", x)).as_deref())
}

fn decode_i64<R: Read>(
    reader: &mut EventReader<R>,
    name: OwnedName,
    attributes: Vec<OwnedAttribute>,
) -> Result<i64, String> {
    decode_optional_i64(reader, name, attributes).map(|x| x.unwrap_or(0))
}

impl<C> KdbxParse<C> for i64 {
    fn parse<R: Read>(
        reader: &mut EventReader<R>,
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
        _context: &mut C,
    ) -> Result<Option<Self>, String> {
        Ok(Some(decode_i64(reader, name, attributes)?))
    }
}

fn encode_i64<W: Write>(writer: &mut EventWriter<W>, value: i64) -> Result<(), String> {
    encode_optional_i64(writer, Some(value))
}

impl<C> KdbxSerialize<C> for i64 {
    fn serialize2<W: Write>(
        writer: &mut EventWriter<W>,
        value: Self,
        _context: &mut C,
    ) -> Result<(), String> {
        encode_i64(writer, value)
    }
}

impl<C> KdbxParse<C> for i32 {
    fn parse<R: Read>(
        reader: &mut EventReader<R>,
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
        _context: &mut C,
    ) -> Result<Option<Self>, String> {
        //decode_i64(reader, name, attributes).map(|v| Some(v as i32))
        Ok(Some(decode_i64(reader, name, attributes)? as i32))
    }
}

impl<C> KdbxSerialize<C> for i32 {
    fn serialize2<W: Write>(
        writer: &mut EventWriter<W>,
        value: Self,
        _context: &mut C,
    ) -> Result<(), String> {
        encode_i64(writer, value as i64)
    }
}

impl<C> KdbxParse<C> for u32 {
    fn parse<R: Read>(
        reader: &mut EventReader<R>,
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
        _context: &mut C,
    ) -> Result<Option<Self>, String> {
        Ok(Some(decode_i64(reader, name, attributes)? as u32))
    }
}

impl<C> KdbxSerialize<C> for u32 {
    fn serialize2<W: Write>(
        writer: &mut EventWriter<W>,
        value: Self,
        _context: &mut C,
    ) -> Result<(), String> {
        encode_i64(writer, value as i64)
    }
}

static mut KDBX4: bool = true;
const KDBX4_TIME_OFFSET: i64 = 62135596800;
fn decode_optional_datetime<R: Read>(
    reader: &mut EventReader<R>,
    name: OwnedName,
    attributes: Vec<OwnedAttribute>,
) -> Result<Option<DateTime<Utc>>, String> {
    let is_new = unsafe { KDBX4 };
    if is_new {
        decode_optional_string(reader, name, attributes).map(|x| {
            x.map(|y| {
                Utc.timestamp_opt(
                    Cursor::new(decode(&y).expect("Valid base64"))
                        .read_i64::<LittleEndian>()
                        .unwrap()
                        - KDBX4_TIME_OFFSET,
                    0,
                ).unwrap()
            })
        })
    } else {
        decode_optional_string(reader, name, attributes).map(|x| {
            x.map(|y| {
                if let Some(suffix) = y.chars().last() {
                    if suffix.to_ascii_uppercase() == 'Z' {
                        DateTime::parse_from_rfc3339(&y)
                            .expect(&format!("failed to parse timestamp: {}", y))
                            .with_timezone(&Utc)
                    } else {
                        NaiveDateTime::parse_from_str(&y, "%Y-%m-%dT%H:%M:%S").expect("invalid local date").and_local_timezone(Local).earliest().unwrap()
                            .with_timezone(&Utc)
                    }
                } else {
                    unreachable!("This shouldn't be possible");
                }
            })
        })
    }
}

fn encode_optional_datetime<W: Write>(
    writer: &mut EventWriter<W>,
    value: Option<DateTime<Utc>>,
) -> Result<(), String> {
    encode_optional_string(
        writer,
        value
            .map(|x| encode(&(x.timestamp() + KDBX4_TIME_OFFSET).to_le_bytes()))
            .as_deref(),
    )
}

// fn decode_datetime<R: Read>(
//     reader: &mut EventReader<R>,
//     name: OwnedName,
//     attributes: Vec<OwnedAttribute>,
// ) -> Result<DateTime<Utc>, String> {
//     decode_optional_datetime(reader, name, attributes).map(|x| x.expect("missing date"))
// }

//impl KdbxDefault for DateTime<Utc> {
//    fn provide_default() -> Self {
//        Utc::now()
//    }
//}

struct KdbxContext {
    major_version: u16,
    inner_cipher_position: usize,
    binaries: Vec<Vec<u8>>,
}

impl Default for KdbxContext {
    fn default() -> Self {
        KdbxContext {
            major_version: 4,
            inner_cipher_position: 0,
            binaries: vec![],
        }
    }
}

impl KdbxParse<KdbxContext> for DateTime<Utc> {
    fn parse<R: Read>(
        reader: &mut EventReader<R>,
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
        context: &mut KdbxContext,
    ) -> Result<Option<Self>, String> {
        unsafe {
            KDBX4 = context.major_version >= 4;
        };
        decode_optional_datetime(reader, name, attributes)
    }
}

fn encode_datetime<W: Write>(
    writer: &mut EventWriter<W>,
    value: DateTime<Utc>,
) -> Result<(), String> {
    encode_optional_datetime(writer, Some(value))
}

impl KdbxSerialize<KdbxContext> for DateTime<Utc> {
    fn serialize2<W: Write>(
        writer: &mut EventWriter<W>,
        value: Self,
        context: &mut KdbxContext,
    ) -> Result<(), String> {
        if context.major_version >= 4 {
            encode_datetime(writer, value)
        } else {
            encode_string(writer, value.format("%FT%TZ").to_string().as_str())
        }
    }
}

//fn decode_i64<R: Read>(reader: &mut EventReader<R>, name: OwnedName, attributes: Vec<OwnedAttribute>) -> Result<DateTime<Utc>, String> {
//decode_optional_i64(reader, name, attributes).map(|x| x.unwrap_or(0))
//}

fn decode_optional_uuid<R: Read>(
    reader: &mut EventReader<R>,
    name: OwnedName,
    attributes: Vec<OwnedAttribute>,
) -> Result<Option<Uuid>, String> {
    decode_optional_string(reader, name, attributes)
        .map(|x| x.map(|y| Uuid::from_slice(&decode(&y).expect("Valid base64")).unwrap()))
}

fn encode_optional_uuid<W: Write>(
    writer: &mut EventWriter<W>,
    value: Option<Uuid>,
) -> Result<(), String> {
    encode_optional_string(writer, value.map(|x| encode(x.as_ref())).as_deref())
}

// fn decode_uuid<R: Read>(
//     reader: &mut EventReader<R>,
//     name: OwnedName,
//     attributes: Vec<OwnedAttribute>,
// ) -> Result<Uuid, String> {
//     decode_optional_uuid(reader, name, attributes).map(|x| x.unwrap_or_else(|| Uuid::default()))
// }

fn encode_uuid<W: Write>(writer: &mut EventWriter<W>, value: Uuid) -> Result<(), String> {
    encode_optional_uuid(writer, Some(value))
}

impl<C> KdbxParse<C> for Uuid {
    fn parse<R: Read>(
        reader: &mut EventReader<R>,
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
        _context: &mut C,
    ) -> Result<Option<Self>, String> {
        decode_optional_uuid(reader, name, attributes)
    }
}

impl<C> KdbxSerialize<C> for Uuid {
    fn serialize2<W: Write>(
        writer: &mut EventWriter<W>,
        value: Self,
        _context: &mut C,
    ) -> Result<(), String> {
        encode_uuid(writer, value)
    }
}

fn decode_item<R: Read>(
    reader: &mut EventReader<R>,
    _name: OwnedName,
    _attributes: Vec<OwnedAttribute>,
) -> Result<(String, String), String> {
    let mut key = String::new();
    let mut value = String::new();

    loop {
        match find_next_element(reader)? {
            ElementEvent::StartElement { name, .. } if name.local_name == "Key" => {
                key = decode_string(reader, name, vec![])?;
            }
            ElementEvent::StartElement { name, .. } if name.local_name == "Value" => {
                value = decode_string(reader, name, vec![])?;
            }
            ElementEvent::StartElement { name, .. } => {
                consume_element(reader, name, vec![])?;
            }
            ElementEvent::EndElement { name, .. } if name.local_name == "Item" => {
                return Ok((key, value));
            }
            ElementEvent::EndElement { .. } => {
                return Err("Wrong ending".to_string());
            }
        }
    }
}

fn encode_item<W: Write>(writer: &mut EventWriter<W>, value: (&str, &str)) -> Result<(), String> {
    writer
        .write(xml::writer::XmlEvent::start_element("Item"))
        .map_err(|_| "")?;
    writer
        .write(xml::writer::XmlEvent::start_element("Key"))
        .map_err(|_| "")?;
    encode_string(writer, value.0)?;
    writer
        .write(xml::writer::XmlEvent::end_element())
        .map_err(|_| "")?;
    writer
        .write(xml::writer::XmlEvent::start_element("Value"))
        .map_err(|_| "")?;
    encode_string(writer, value.1)?;
    writer
        .write(xml::writer::XmlEvent::end_element())
        .map_err(|_| "")?;
    writer
        .write(xml::writer::XmlEvent::end_element())
        .map_err(|_| "")?;
    Ok(())
}

fn decode_custom_data<R: Read>(
    reader: &mut EventReader<R>,
    pname: OwnedName,
    _attributes: Vec<OwnedAttribute>,
) -> Result<HashMap<String, String>, String> {
    //let mut elements = vec![];
    //elements.push(name);

    let mut data = HashMap::new();

    loop {
        match find_next_element(reader)? {
            ElementEvent::StartElement { name, .. } if name.local_name == "Item" => {
                let (key, value) = decode_item(reader, name, vec![])?;
                //data[key] = value;
                data.insert(key, value);
            }
            ElementEvent::StartElement { name, .. } => {
                consume_element(reader, name, vec![])?;
            }
            ElementEvent::EndElement { name, .. } if name == pname => {
                return Ok(data);
            }
            ElementEvent::EndElement { .. } => {
                return Err("Wrong ending".to_string());
            }
        }
    }
}

fn encode_custom_data<W: Write>(
    writer: &mut EventWriter<W>,
    map: HashMap<String, String>,
) -> Result<(), String> {
    for (key, value) in map.iter() {
        encode_item(writer, (key, value))?;
    }
    Ok(())
}

#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize)]
struct MemoryProtection {
    protect_title: bool,
    protect_user_name: bool,
    protect_password: bool,
    #[keepass_db(element = "ProtectURL")]
    protect_url: bool,
    protect_notes: bool,
}

#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize)]
struct Icon {
    #[keepass_db(element = "UUID")]
    uuid: Uuid,
    last_modification_time: Option<DateTime<Utc>>,
    data: Vec<u8>,
}

#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Item {
    key: String,
    value: String,
    // This field only seems to be present on Meta data, not password entries
    last_modification_time: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize)]
struct Meta {
    generator: String,
    header_hash: Option<[u8; 32]>,
    settings_changed: Option<DateTime<Utc>>,
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
    master_key_change_force_once: bool,
    memory_protection: MemoryProtection,
    custom_icons: Vec<Icon>,
    recycle_bin_enabled: bool,
    #[keepass_db(element = "RecycleBinUUID")]
    recycle_bin_uuid: Option<Uuid>,
    recycle_bin_changed: DateTime<Utc>,
    entry_templates_group: Uuid,  // TODO should be optional?
    entry_templates_group_changed: DateTime<Utc>,
    history_max_items: i32,  // -1 = unlimited
    history_max_size: i64,  // -1 = unlimited
    last_selected_group: Uuid,  // TODO should be optional?
    last_top_visible_group: Uuid,  // TODO should be optional?
    //custom_data: HashMap<String, String>,
    custom_data: Vec<Item>,
}

impl<C> KdbxParse<C> for [u8; 32] {
    fn parse<R: Read>(
        reader: &mut EventReader<R>,
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
        _context: &mut C,
    ) -> Result<Option<Self>, String> {
        //decode_optional_string(reader, name, attributes)
        //Ok(decode_base64(reader, name, attributes)?.map(|v| Some(v.try_into().map_err(|_| "")?))?)
        Ok(Some(
            decode_base64(reader, name, attributes)?
                .try_into()
                .map_err(|_| "")?,
        ))
    }
}

impl<C> KdbxSerialize<C> for [u8; 32] {
    fn serialize2<W: Write>(
        writer: &mut EventWriter<W>,
        value: Self,
        _context: &mut C,
    ) -> Result<(), String> {
        encode_base64(writer, value)
    }
}

impl<C> KdbxParse<C> for Vec<u8> {
    fn parse<R: Read>(
        reader: &mut EventReader<R>,
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
        _context: &mut C,
    ) -> Result<Option<Self>, String> {
        //decode_optional_string(reader, name, attributes)
        //Ok(decode_base64(reader, name, attributes)?.map(|v| Some(v.try_into().map_err(|_| "")?))?)
        Ok(Some(
            decode_base64(reader, name, attributes)?
                .try_into()
                .map_err(|_| "")?,
        ))
    }
}

impl<C> KdbxSerialize<C> for Vec<u8> {
    fn serialize2<W: Write>(
        writer: &mut EventWriter<W>,
        value: Self,
        _context: &mut C,
    ) -> Result<(), String> {
        encode_base64(writer, value)
    }
}

impl<C> KdbxParse<C> for HashMap<String, String> {
    fn parse<R: Read>(
        reader: &mut EventReader<R>,
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
        _context: &mut C,
    ) -> Result<Option<Self>, String> {
        Ok(Some(decode_custom_data(reader, name, attributes)?))
    }
}

impl<C> KdbxSerialize<C> for HashMap<String, String> {
    fn serialize2<W: Write>(
        writer: &mut EventWriter<W>,
        value: Self,
        _context: &mut C,
    ) -> Result<(), String> {
        encode_custom_data(writer, value)
    }
}

#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize)]
//#[derive(Debug, Default, KdbxParse)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Times {
    creation_time: DateTime<Utc>,
    last_modification_time: DateTime<Utc>,
    last_access_time: DateTime<Utc>,
    expiry_time: DateTime<Utc>,
    expires: bool,
    usage_count: i32,
    location_changed: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize)]
#[cfg_attr(test, derive(PartialEq))]
struct ProtectedString {
    key: String,
    value: ProtectedValue,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ProtectedValue {
    Unprotected(String),
    Protected(usize, Vec<u8>),
}

use protected_stream::CipherValue;

impl ProtectedValue {
    pub fn unprotect(&self, cipher: &mut CipherValue) -> Result<String, String> {
        match self {
            Self::Unprotected(ref v) => Ok(v.clone()),
            Self::Protected(offset, bytes) => {
                let mut value = bytes.clone();
                cipher.apply_keystream_pos(&mut value, *offset);
                String::from_utf8(value).map_err(|_| "Invalid UTF-8".to_string())
            }
        }
    }
}

impl Default for ProtectedValue {
    fn default() -> Self {
        Self::Unprotected("".to_string())
    }
}

impl KdbxParse<KdbxContext> for ProtectedValue {
    fn parse<R: Read>(
        reader: &mut EventReader<R>,
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
        context: &mut KdbxContext,
    ) -> Result<Option<Self>, String> {
        let protected = attributes.iter().filter(|a| a.name.local_name == "Protected").last().map(|v| v.value.to_ascii_lowercase() == "true").unwrap_or(false);
        if protected {
            decode_optional_base64(reader, name, attributes).map(|o| o.map(|v| { let offset = context.inner_cipher_position; context.inner_cipher_position += v.len(); Self::Protected(offset, v)}))
        } else {
            decode_optional_string(reader, name, attributes).map(|o| o.map(|v| Self::Unprotected(v)))
        }
//        loop {
//            let event = reader.next().unwrap();
//            match event {
//                XmlEvent::StartDocument { .. } => {
//                    println!("Start");
//                }
//                XmlEvent::StartElement {
//                    name, attributes, ..
//                } => {
//                    // TODO Check top-level tag name
//                    let mut context = KdbxContext::default();
//                    context.major_version = major_version;
//                    my_doc = Some(KeePassFile::parse(&mut reader, name, attributes, &mut context)
//                        .map_err(|x| ::std::io::Error::new(::std::io::ErrorKind::Other, x))?
//                        .unwrap());
//                }
//                XmlEvent::EndDocument => {
//                    println!("End");
//                    break;
//                }
//                _ => {}
//            }
//        }
    }
}

impl<C> KdbxSerialize<C> for ProtectedValue {
    fn serialize2<W: Write>(
        writer: &mut EventWriter<W>,
        value: Self,
        _context: &mut C,
    ) -> Result<(), String> {
        //encode_string(writer, &value)
        Ok(())
    }
}

#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize)]
#[cfg_attr(test, derive(PartialEq))]
struct ProtectedBinary {
    key: String,
    value: BinaryRef,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
struct BinaryRef(Vec<u8>);

impl BinaryRef {
}

impl Default for BinaryRef {
    fn default() -> Self {
        Self(vec![])
    }
}

impl KdbxParse<KdbxContext> for BinaryRef {
    fn parse<R: Read>(
        reader: &mut EventReader<R>,
        name: OwnedName,
        attributes: Vec<OwnedAttribute>,
        context: &mut KdbxContext,
    ) -> Result<Option<Self>, String> {
        use std::str::FromStr;
        let id = attributes.iter().filter(|a| a.name.local_name == "Ref").last().and_then(|v| usize::from_str(v.value.as_str()).ok()).unwrap_or(0);
        loop {
            let event = reader.next().unwrap();
            match event {
                XmlEvent::StartDocument { .. } => {
                    return Err("Malformed XML document".to_string());
                }
                XmlEvent::EndDocument { .. } => {
                    return Err("Malformed XML document".to_string());
                }
                XmlEvent::StartElement { .. } => {
                    reader.skip();
                }
                XmlEvent::EndElement { .. } => {
                    return Ok(Some(Self(context.binaries.get(id).map(|v| v.clone()).unwrap_or_else(|| vec![]))));
                }
                _ => {}
            }
        }
    }
}

impl<C> KdbxSerialize<C> for BinaryRef {
    fn serialize2<W: Write>(
        writer: &mut EventWriter<W>,
        value: Self,
        _context: &mut C,
    ) -> Result<(), String> {
        //encode_string(writer, &value)
        Ok(())
    }
}


#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize, Getters)]
pub struct Group {
    #[keepass_db(element = "UUID")]
    uuid: Uuid,
    name: String,
    notes: String,
    #[keepass_db(element = "IconID")]
    icon_id: u32,
    #[keepass_db(element = "CustomIconUUID")]
    custom_icon_uuid: Option<Uuid>,
    times: Times,
    is_expanded: bool,
    default_auto_type_sequence: String,
    enable_auto_type: bool,
    enable_searching: bool,
    last_top_visible_entry: Uuid,
    // TODO custom_data: CustomData,
    previous_parent_group: Option<Uuid>,
    tags: Option<String>,  // TODO Should be a Vec
    #[keepass_db(flatten)]
    #[getter(rename = "entries")]
    entry: Vec<Entry>,
    #[keepass_db(flatten)]
    #[getter(rename = "groups")]
    group: Vec<Group>,
}

impl Group {
//    pub fn groups(&self) -> Iter<'_, Group> {
//        self.group.iter()
//    }
//
//    pub fn entries(&self) -> Iter<'_, Entry> {
//        self.entry.iter()
//    }

    pub fn all_groups(&self) -> GroupIter {
        return GroupIter {
            first: true,
            group: self,
            children: self.group.iter(),
            next_group: None,
        }
    }

    pub fn all_entries(&self) -> EntryIter {
        let mut groups = self.all_groups();
        return EntryIter {
            entries: groups.next().map(|e| e.entries().iter()),
            groups,
        }
    }
}

pub struct GroupIter<'a> {
    first: bool,
    group: &'a Group,
    children: Iter<'a, Group>,
    next_group: Option<Box<GroupIter<'a>>>,
}

impl<'a> Iterator for GroupIter<'a> {
    type Item = &'a Group;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first {
            self.first = false;
            self.next_group = self.children.next().map(|c| Box::new(c.all_groups()));
            Some(self.group)
        } else {
            if let Some(ref mut child) = self.next_group {
                if let Some(g) = child.next() {
                    Some(g)
                } else {
                    self.next_group = self.children.next().map(|c| Box::new(c.all_groups()));
                    if let Some(ref mut child) = self.next_group {
                        if let Some(g) = child.next() {
                            Some(g)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            } else {
                None
            }
        }
    }
}

pub struct EntryIter<'a> {
    entries: Option<Iter<'a, Entry>>,
    groups: GroupIter<'a>,
}

impl<'a> Iterator for EntryIter<'a> {
    type Item = &'a Entry;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(ref mut d) = self.entries {
            if let Some(e) = d.next() {
                return Some(e);
            } else {
                self.entries = self.groups.next().map(|e| e.entries().iter());
            }
        }
        None
    }
}

#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize)]
#[cfg_attr(test, derive(PartialEq))]
struct Association {
    window: String,
    keystroke_sequence: String,
}

#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize)]
#[cfg_attr(test, derive(PartialEq))]
struct AutoType {
    enabled: bool,
    data_transfer_obfuscation: i64,
    default_sequence: Option<String>,
    #[keepass_db(flatten)]
    association: Vec<Association>,
}

#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize, Getters)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Entry {
    #[keepass_db(element = "UUID")]
    uuid: Uuid,
    #[keepass_db(element = "IconID")]
    icon_id: u32,
    #[keepass_db(element = "CustomIconUUID")]
    custom_icon_uuid: Option<Uuid>,
    foreground_color: String,
    background_color: String,
    #[keepass_db(element = "OverrideURL")]
    override_url: String,
    quality_check: Option<bool>,
    tags: String,
    previous_parent_group: Option<Uuid>,
    times: Times,
    custom_data: Vec<Item>,
    #[keepass_db(flatten)]
    #[getter(skip)]
    string: Vec<ProtectedString>,
    #[keepass_db(flatten)]
    #[getter(skip)]
    binary: Vec<ProtectedBinary>,
    #[getter(skip)]
    auto_type: AutoType,
    history: Option<Vec<Entry>>,
}

const TITLE_FIELD: &str = "Title";
const USER_NAME_FIELD: &str = "UserName";
const PASSWORD_FIELD: &str = "Password";
const URL_FIELD: &str = "URL";
const NOTES_FIELD: &str = "Notes";

impl Entry {
    pub fn title(&self) -> ProtectedValue {
        self.string.iter().find(|p| p.key == TITLE_FIELD).map(|p| p.value.clone()).unwrap_or(ProtectedValue::Unprotected("".to_string()))
    }

    pub fn username(&self) -> ProtectedValue {
        self.string.iter().find(|p| p.key == USER_NAME_FIELD).map(|p| p.value.clone()).unwrap_or(ProtectedValue::Unprotected("".to_string()))
    }

    pub fn password(&self) -> ProtectedValue {
        self.string.iter().find(|p| p.key == PASSWORD_FIELD).map(|p| p.value.clone()).unwrap_or(ProtectedValue::Unprotected("".to_string()))
    }

    pub fn url(&self) -> ProtectedValue {
        self.string.iter().find(|p| p.key == URL_FIELD).map(|p| p.value.clone()).unwrap_or(ProtectedValue::Unprotected("".to_string()))
    }

    pub fn notes(&self) -> ProtectedValue {
        self.string.iter().find(|p| p.key == NOTES_FIELD).map(|p| p.value.clone()).unwrap_or(ProtectedValue::Unprotected("".to_string()))
    }

    pub fn get_binary(&self, index: usize) -> (&str, &[u8]) {
        (self.binary[index].key.as_ref(), self.binary[index].value.0.as_ref())
    }
}

#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize)]
pub struct DeletedObject {
    #[keepass_db(element = "UUID")]
    uuid: Uuid,
    deletion_time: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize, Getters)]
pub struct Root {
    #[keepass_db(flatten)]
    group: Vec<Group>,
    deleted_objects: Vec<DeletedObject>,
}

#[derive(Clone, Debug, Default, KdbxParse, KdbxSerialize)]
pub struct KeePassFile {
    meta: Meta,
    root: Root,
}

impl KeePassFile {
//    pub fn groups(&self) -> Iter<'_, Group> {
//        self.root.group.iter()
//    }
    pub fn groups(&self) -> &Vec<Group> {
        &self.root.group
    }
}

const KDBX_MAGIC: u32 = 0x9AA2D903;

const KDBX1_MAGIC_TYPE: u32 = 0xB54BFB65;
const KDBX2_BETA_MAGIC_TYPE: u32 = 0xB54BFB66;
const KDBX2_MAGIC_TYPE: u32 = 0xB54BFB67;

pub fn save_file(doc: &KeePassFile, major_version: u16) -> io::Result<()> {
    let mut file = File::create("data-out.kdbx")?;
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
    custom_data.insert(
        KDF_PARAM_UUID.to_string(),
        MapValue::ByteArray(KDF_AES_KDBX3.into_bytes().to_vec()),
    );
    kdf.save(&mut custom_data);
    let transform_key = kdf
        .transform_key(&composite_key)
        .expect("Failed to transform key");
    let master_seed = [0u8; 32];
    let iv = [0u8; 16];
    let stream_cipher = 2u32;
    let stream_key = [0u8; 32];
    let mut tlvs = BTreeMap::new();
    tlvs.insert(
        TlvType::MasterSeed.to_u8().unwrap(),
        vec![master_seed.to_vec()],
    );
    tlvs.insert(
        TlvType::CipherId.to_u8().unwrap(),
        vec![CIPHER_ID_AES256_CBC.into_bytes().to_vec()],
    );
    tlvs.insert(TlvType::EncryptionIv.to_u8().unwrap(), vec![iv.to_vec()]);
    tlvs.insert(
        TlvType::CompressionFlags.to_u8().unwrap(),
        vec![Compression::None.to_u32().unwrap().to_le_bytes().to_vec()],
    );
    let start_stream = vec![0; 32]; // TODO Randomize this
    if major_version < 4 {
        tlvs.insert(
            TlvType::TransformSeed.to_u8().unwrap(),
            vec![master_seed.to_vec()],
        );
        tlvs.insert(
            TlvType::TransformRounds.to_u8().unwrap(),
            vec![match custom_data[KDF_PARAM_ROUNDS] {
                MapValue::UInt64(x) => x.to_le_bytes().to_vec(),
                _ => panic!("Wrong"),
            }],
        );
        tlvs.insert(
            TlvType::StreamStartBytes.to_u8().unwrap(),
            vec![start_stream.to_vec()],
        );
        tlvs.insert(
            TlvType::ProtectedStreamKey.to_u8().unwrap(),
            vec![stream_key.to_vec()],
        );
        tlvs.insert(
            TlvType::InnerRandomStreamId.to_u8().unwrap(),
            vec![stream_cipher.to_le_bytes().to_vec()],
        );
    } else {
        tlvs.insert(
            TlvType::KdfParameters.to_u8().unwrap(),
            vec![save_map(&custom_data)],
        );
    }
    header.append(&mut save_tlvs(&mut io::sink(), &tlvs, major_version).unwrap());
    file.write(&header)?;
    let mut context = Context::new(&SHA256);
    context.update(&header);
    let digest = context.finish();
    if major_version >= 4 {
        file.write(digest.as_ref())?;
        // header.append(&mut digest.as_ref().to_owned());
    }

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
    if major_version >= 4 {
        file.write(hmac_tag.as_ref())?;
    } else {
        let output = Cursor::new(Vec::<u8>::new());
        let mut context = KdbxContext::default();
        context.major_version = major_version;
        let mut writer = xml::writer::EventWriter::new(output);
        writer
            .write(xml::writer::XmlEvent::start_element("KeePassFile"))
            .expect("Success!");
        KeePassFile::serialize2(&mut writer, doc.clone(), &mut context).unwrap();
        writer
            .write(xml::writer::XmlEvent::end_element())
            .expect("Success!");
        let output = writer.into_inner().into_inner();
        let mut buf = Cursor::new(Vec::<u8>::new());
        buf.write_all(&start_stream).unwrap();
        buf.write_all(&0u32.to_le_bytes()).unwrap();
        let mut context = Context::new(&SHA256);
        context.update(&output);
        buf.write_all(&context.finish().as_ref().to_owned()).unwrap();
        buf.write_all(&(output.len() as u32).to_le_bytes()).unwrap();
        buf.write_all(&output).unwrap();
        buf.write_all(&1u32.to_le_bytes()).unwrap();
        let context = Context::new(&SHA256);
        buf.write_all(&context.finish().as_ref().to_owned()).unwrap();
        //buf.write_all(&[0u8; 32]).unwrap();
        buf.write_all(&0u32.to_le_bytes()).unwrap();
        let data = encrypt(
            Cipher::aes_256_cbc(),
            &master_key,
            Some(&iv),
            &buf.into_inner(),
        ).unwrap();
        file.write_all(&data).unwrap();
        return Ok(());
    }

    let output = BlockWriter::new(&hmac_key_base, file);
    let cipher = Cipher::aes_256_cbc();
    let mut output = Crypto::new(cipher, &master_key, Some(&iv), output).unwrap();

    if major_version >= 4 {
        let mut inner_tlvs = BTreeMap::new();
        inner_tlvs.insert(1, vec![stream_cipher.to_le_bytes().to_vec()]);
        inner_tlvs.insert(2, vec![stream_key.to_vec()]);
        save_tlvs(&mut output, &inner_tlvs, major_version).unwrap();
    }
    let mut writer = xml::writer::EventWriter::new(output);
    writer
        .write(xml::writer::XmlEvent::start_element("KeePassFile"))
        .expect("Success!");
    KeePassFile::serialize2(&mut writer, doc.clone(), &mut KdbxContext::default()).unwrap();
    writer
        .write(xml::writer::XmlEvent::end_element())
        .expect("Success!");
    let mut output = writer.into_inner();
    output.flush()?;
    // output.flush()?;
    // drop(output);

    Ok(())
}

#[derive(Default)]
pub struct KeePassDoc {
    pub file: KeePassFile,
    pub cipher: CipherValue,
}

impl std::fmt::Debug for KeePassDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeePassDoc")
            .field("file", &self.file)
            .finish()
    }
}

/// This is a temporary solution until a proper API is ready
/// ```
/// assert!(true);
/// ```
/// Does it work?
pub fn lib_main(filename: &str, key: &Key) -> io::Result<KeePassDoc> {
    let composite_key = key.composite_key();

    let mut file = File::open(filename)?;
    let magic = file.read_u32::<LittleEndian>()?;
    let magic_type = file.read_u32::<LittleEndian>()?;

    if magic != KDBX_MAGIC {
        eprintln!("Invalid database file\n");
        process::exit(1);
    }

    let mut custom_data = HashMap::<String, Vec<u8>>::new();
    let mut custom_data2 = HashMap::<_, _>::new();

    match magic_type {
        KDBX1_MAGIC_TYPE => {
            use kdb1::read_kdb1_header;
            read_kdb1_header(&mut file, &key)?;
            return Ok(KeePassDoc::default());
        }
        // KDBX2_BETA_MAGIC_TYPE => {
        //     // XXX Untested
        //     eprintln!("KeePass 2.x Beta files not supported\n");
        //     process::exit(1);
        // },
        KDBX2_MAGIC_TYPE | KDBX2_BETA_MAGIC_TYPE => {
            println!("Opening KeePass 2.x database");
        }
        _ => {
            // XXX Untested
            eprintln!("Unknown KeePass database format\n");
            process::exit(1);
        }
    };

    // Version field is defined as uint32_t, but it's broken up into
    // major and minor 16-bit components. Due to the nature of little
    // endian, this puts the minor part first.
    let minor_version = file.read_u16::<LittleEndian>()?;
    let major_version = file.read_u16::<LittleEndian>()?;
    match major_version {
        3 => {
            unsafe {
                KDBX4 = false;
            };
            custom_data.insert(
                KDF_PARAM_UUID.to_string(),
                KDF_AES_KDBX3.as_bytes().to_vec(),
            );
        }
        4 => {}
        1 => {
            custom_data.insert(
                KDF_PARAM_UUID.to_string(),
                KDF_AES_KDBX3.as_bytes().to_vec(),
            );
        }
        _ => {
            eprintln!(
                "Unsupported KeePass 2.x database version ({}.{})\n",
                major_version, minor_version
            );
            process::exit(1);
        }
    };
    let mut tlvs = HashMap::new();
    let mut inner_tlvs = BTreeMap::<u8, Vec<Vec<u8>>>::new();
    inner_tlvs.insert(3u8, vec![]);
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
            0 => {
                break;
            }
            5 => {
                custom_data.insert(KDF_PARAM_SALT.to_string(), tlv_data.clone());
                custom_data2.insert(KDF_PARAM_SALT.to_string(), MapValue::ByteArray(tlv_data));
            }
            6 => {
                custom_data.insert(KDF_PARAM_ROUNDS.to_string(), tlv_data.clone());
                custom_data2.insert(
                    KDF_PARAM_ROUNDS.to_string(),
                    MapValue::UInt64(u64::from_le_bytes(tlv_data[0..8].try_into().unwrap())),
                );
            }
            8 => {
                inner_tlvs.insert(2u8, vec![tlv_data]);
            }
            10 => {
                inner_tlvs.insert(1u8, vec![tlv_data]);
            }
            11 => {
                custom_data2 = load_map(&tlv_data).unwrap();
                let kdf_parameters = &tlv_data;
                let mut c = Cursor::new(kdf_parameters);
                let variant_minor = c.read_u8()?;
                let variant_major = c.read_u8()?;
                if variant_major != 1 {
                    eprintln!(
                        "Unsupported variant dictionary version ({}.{})\n",
                        variant_major, variant_minor
                    );
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
            }
            _ => {
                tlvs.insert(tlv_type, tlv_data);
            }
        }
    }

    //let src = &tlvs[&2u8];
    //let mut uuid = [0; 16];
    //let b = &src[..uuid.len()];
    //uuid.copy_from_slice(b);
    //let d = Builder::from_bytes(uuid).build();
    let cipher_id = Uuid::from_slice(&tlvs[&2u8]).unwrap();
    println!("D: {:?}", cipher_id);
    if cipher_id != CIPHER_ID_AES256_CBC {
        eprintln!("Unknown cipher\n");
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
            // eprintln!("Unsupported no compressed file\n");
            //process::exit(1);
            Compression::None
        }
        1 => {
            println!("Gzip compression");
            Compression::Gzip
        }
        _ => {
            // XX Untested
            eprintln!("Unsupported compression method\n");
            process::exit(1);
        }
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
            eprintln!("Possible header corruption\n");
            process::exit(1);
        }
    }

    let kdf_id = Uuid::from_slice(&custom_data[KDF_PARAM_UUID]).unwrap();
    println!("KDF: {:?}", kdf_id);

    let transform_key = match kdf_id {
        x if x == KDF_AES_KDBX3 => {
            //unimplemented!("KDBX 3 AES-KDF not supported!");
            AesKdf::load(&custom_data2)?.transform_key(&composite_key)?
            // transform_aes_kdf(&composite_key, &custom_data)?
        }
        x if x == KDF_AES_KDBX4 => {
            unimplemented!("KDBX 4 AES-KDF not supported!");
        }
        x if x == KDF_ARGON2_D => {
            transform_argon2(&composite_key, &custom_data)?
            //unimplemented!("Argon2 KDF not supported!");
        }
        _ => {
            unimplemented!("Unknown");
        }
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

        let data = decrypt(
            Cipher::aes_256_cbc(),
            &master_key,
            Some(encryption_iv),
            &ciphertext,
        )
        .unwrap();
        // let mut gz = if let compress = Compression::None {
        //     GzDecoder::new(Cursor::new(data))
        // } else{
        //     GzDecoder::new(Cursor::new(data))
        // };
        let mut gz: Box<dyn Read> = match compress {
            Compression::Gzip => Box::new(GzDecoder::new(Cursor::new(data))),
            Compression::None => Box::new(Cursor::new(data)),
        };

        inner_tlvs = load_tlvs(&mut gz, major_version)?.0;
        let mut contents = String::new();
        gz.read_to_string(&mut contents)?;
        contents
    } else {
        /* KDBX 3.x format encrypts the database after breaking
         * the stream into blocks */
        let mut ciphertext = vec![];
        file.read_to_end(&mut ciphertext)?;
        let data = decrypt(
            Cipher::aes_256_cbc(),
            &master_key,
            Some(encryption_iv),
            &ciphertext,
        )
        .unwrap();
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
        let mut gz: Box<dyn Read> = match compress {
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
        let header_hash = evaluate_xpath(&document, "/KeePassFile/Meta/HeaderHash/text()")
            .expect("Missing header hash");
        if header_hash.string() != "" {
            println!("Header Hash: '{}'", header_hash.string());
            let expected_hash = decode(&header_hash.string()).expect("Valid base64");
            if expected_hash != digest.as_ref() {
                eprintln!("Possible header corruption\n");
                process::exit(1);
            }
        }
        contents
    };

    let default = vec![vec![1, 0, 0, 0]];
    let inner_stream_cipher = &inner_tlvs.get(&1u8).unwrap_or(&default)[0];  // Defaults to ARC4
    if inner_stream_cipher.len() != 4 {
        panic!("Invalid inner cipher");
    }
    let inner_cipher_type = u32::from_le_bytes(inner_stream_cipher[..].try_into().unwrap());
    println!("Inner Cipher: {inner_cipher_type}");
    let p_key = &inner_tlvs[&0x02u8][0];
    println!("p_key: {p_key:02x?} ({})", p_key.len());
    let mut inner_cipher = protected_stream::new_stream(inner_cipher_type, p_key).expect("Unknown inner cipher");

    let mut xml_file = File::create("data.xml")?;
    let _ = xml_file.write(&contents.as_bytes());
    const KDBX4_TIME_OFFSET: i64 = 62135596800;
    println!("XML Body len: {}", contents.len());
    let package = parser::parse(&contents).unwrap();
    let document = package.as_document();
    println!(
        "Root element: {}",
        document.root().children()[0]
            .element()
            .unwrap()
            .name()
            .local_part()
    );
    let database_name_node = evaluate_xpath(&document, "/KeePassFile/Meta/DatabaseName/text()")
        .expect("Missing database name");
    println!("Database Name: {}", database_name_node.string());
    let database_name_changed_node =
        evaluate_xpath(&document, "/KeePassFile/Meta/DatabaseNameChanged/text()")
            .expect("Missing database name changed");
    let change_time = if database_name_changed_node.string() == "" {
        "<missing>".to_owned()
    } else {
        let datetime: DateTime<Local> = if major_version <= 3 {
            DateTime::parse_from_rfc3339(&database_name_changed_node.string())
                .expect("failed to parse timestamp")
                .with_timezone(&Local)
        } else {
            let timestamp =
                Cursor::new(decode(&database_name_changed_node.string()).expect("Valid base64"))
                    .read_i64::<LittleEndian>()?
                    - KDBX4_TIME_OFFSET;
            //let naive = NaiveDateTime::from_timestamp(timestamp, 0);
            //let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
            Local.timestamp_opt(timestamp, 0).unwrap()
        };
        datetime.format("%Y-%m-%d %l:%M:%S %p %Z").to_string()
    };
    println!("Database Name Changed: {}", change_time);

    let xpath_context = XPathContext::new();
    let protected_nodes = evaluate_xpath(&document, "//Value[@Protected = 'True']/text()")
        .expect("Missing database entries");
    let xpath_current = Factory::new()
        .build(".")
        .expect("Failed to compile XPath")
        .expect("Empty XPath expression");
    let mut protected_offset = 0;
    match protected_nodes {
        Value::Nodeset(nodes) => {
            for entry in nodes.document_order() {
                let p = xpath_current
                    .evaluate(&xpath_context, entry)
                    .expect("Missing entry text");
                println!("P: {:?}, ('{}')", p, p.string());
                let mut p_ciphertext = decode(&p.string()).expect("Valid base64");
                println!("Protected Value Ciphertext: {p_ciphertext:#04X?} (+{protected_offset})");
                protected_offset += p_ciphertext.len();
                inner_cipher.apply_keystream(&mut p_ciphertext);
                println!("Protected Value Plaintext: {p_ciphertext:#04X?}");
                let value = String::from_utf8(p_ciphertext)
                    .unwrap_or("«Failed to decrypt value»".to_owned());
                println!("Protected Value: {:?}", &value);
                match entry {
                    sxd_xpath::nodeset::Node::Text(t) => {
                        t.set_text(&value);
                    }
                    _ => {}
                }
            }
        }
        _ => {
            panic!("XML corruption");
        }
    }
    let xpath_username = Factory::new()
        .build("String[Key/text() = 'UserName']/Value/text()")
        .expect("Failed to compile XPath")
        .expect("Empty XPath expression");
    let xpath_last_mod_time = Factory::new()
        .build("Times/LastModificationTime/text()")
        .expect("Failed to compile XPath")
        .expect("Empty XPath expression");
    let xpath_password = Factory::new()
        .build("String[Key/text() = 'Password']/Value[@Protected = 'True']/text()")
        .expect("Failed to compile XPath")
        .expect("Empty XPath expression");
    //let entry_nodes = evaluate_xpath(&document, "/KeePassFile/Root/Group/Entry").expect("Missing database entries");
    let entry_nodes = evaluate_xpath(&document, "//Entry").expect("Missing database entries");
    match entry_nodes {
        Value::Nodeset(nodes) => {
            for entry in nodes.document_order() {
                //let n = evaluate_xpath(&document, "/KeePassFile/Root/Group/Entry/String[Key/text() = 'UserName']/Value/text()").expect("Missing entry username");
                let n = xpath_username
                    .evaluate(&xpath_context, entry)
                    .expect("Missing entry username");
                let t = xpath_last_mod_time
                    .evaluate(&xpath_context, entry)
                    .expect("Missing entry modification");
                let p = xpath_password
                    .evaluate(&xpath_context, entry)
                    .expect("Missing entry password");
                println!("Name: {}", n.string());
                let change_time = if database_name_changed_node.string() == "" {
                    "<missing>".to_owned()
                } else {
                    let datetime: DateTime<Local> = if major_version <= 3 {
                        DateTime::parse_from_rfc3339(&t.string())
                            .expect("failed to parse timestamp")
                            .with_timezone(&Local)
                    } else {
                        println!("Inner: {:?}", &t.string());
                        let timestamp =
                            Cursor::new(decode(&t.string()).expect("Valid base64"))
                                .read_i64::<LittleEndian>()?
                                - KDBX4_TIME_OFFSET;
                        //let naive = NaiveDateTime::from_timestamp(timestamp, 0);
                        //let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
                        Local.timestamp_opt(timestamp, 0).unwrap()
                    };
                    datetime.format("%Y-%m-%d %l:%M:%S %p %Z").to_string()
                };
                println!("Changed: {}", change_time);
                println!("Password: {:?}", p.string());
            }
        }
        _ => {
            panic!("XML corruption");
        }
    };

    let content_cursor = Cursor::new(&contents);
    let mut reader = ParserConfig::new()
        .cdata_to_characters(true)
        .create_reader(content_cursor);
    let mut my_doc = None;
    loop {
        let event = reader.next().unwrap();
        match event {
            XmlEvent::StartDocument { .. } => {
                println!("Start");
            }
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                // TODO Check top-level tag name
                let mut context = KdbxContext::default();
                context.major_version = major_version;
                context.binaries = inner_tlvs.remove(&3u8).unwrap();
                my_doc = Some(KeePassFile::parse(&mut reader, name, attributes, &mut context)
                    .map_err(|x| ::std::io::Error::new(::std::io::ErrorKind::Other, x))?
                    .unwrap());
            }
            XmlEvent::EndDocument => {
                println!("End");
                break;
            }
            _ => {}
        }
    }

    Ok(KeePassDoc {
        file: my_doc.expect("Missing top-level element"),
        cipher: inner_cipher,
    })
}
