extern crate byteorder;
extern crate uuid;
extern crate ring;
extern crate rpassword;
extern crate openssl;

use std::io::Cursor;
use std::env;
use std::process;
use std::fs::File;
use std::io::{self, SeekFrom};
use std::io::prelude::*;
use std::collections::HashMap;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use uuid::{Builder, Uuid};
use ring::digest::{Context, SHA256, SHA512};
use ring::hmac;
use rpassword::read_password;
use openssl::symm::{encrypt, Crypter, Cipher, Mode};

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
        println!("K: {}, V: {:?}", item_key_str, item_value);
        custom_data.insert(item_key_str.to_owned().to_string(), item_value);
    }

    let context = Context::new(&SHA256);
    let digest = context.finish();
    println!("{:?}", digest);

    let mut context = Context::new(&SHA256);
    let header_start = 0;
    let pos = file.seek(SeekFrom::Current(0))?;
    file.seek(SeekFrom::Start(header_start))?;
    let mut header = vec![0; (pos-header_start) as usize];
    file.read_exact(&mut header)?;
    file.seek(SeekFrom::Start(pos))?;
    context.update(&header);
    let digest = context.finish();
    println!("{:?}", digest);
    let mut expected_hash = [0; 32];
    file.read_exact(&mut expected_hash)?;
    if digest.as_ref() != expected_hash {
        writeln!(stderr, "Possible header corruption\n")?;
        process::exit(1);
    }

    let mut composite_key_intermediate = Vec::<u8>::new();

    let user_password = read_password().unwrap();
    {
        let mut context = Context::new(&SHA256);
        context.update(&user_password.as_bytes());
        let digest = context.finish();
        composite_key_intermediate.extend(digest.as_ref());
    }

    let keyfile: Option<Vec<u8>> = None;
    if let Some(key) = keyfile {
        let mut context = Context::new(&SHA256);
        context.update(&key);
        let digest = context.finish();
        composite_key_intermediate.extend(digest.as_ref());
    }

    let windows_credentials: Option<Vec<u8>> = None;
    if let Some(key) = windows_credentials {
        let mut context = Context::new(&SHA256);
        context.update(&key);
        let digest = context.finish();
        composite_key_intermediate.extend(digest.as_ref());
    }

    let composite_key = {
        let mut context = Context::new(&SHA256);
        context.update(&composite_key_intermediate);
        context.finish()
    };

    let transform_seed = &custom_data["S"];
    let mut c = Cursor::new(&custom_data["R"]);
    let transform_round = c.read_u64::<LittleEndian>()?;

    println!("Calculating transformed key ({})", transform_round);

    let mut transform_key = composite_key.as_ref().to_owned();
    let cipher = Cipher::aes_256_ecb();
    let mut c = Crypter::new(cipher, Mode::Encrypt, transform_seed, None)?;
    for i in 0..cipher.block_size() {
        transform_key.push(0);
    }
    let mut out = vec![0; 16 + 16 + cipher.block_size()];
    c.pad(false);
    for i in 0..transform_round {
        let count = c.update(&transform_key[0..32], &mut out)?;
        let temp = transform_key;
        transform_key = out;
        out = temp;
    }
    transform_key.truncate(32);
    let mut context = Context::new(&SHA256);
    context.update(&transform_key);
    transform_key = context.finish().as_ref().to_owned();
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
    println!("HMAC Tag: {:0x?}", hmac_tag);
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
        buf.write_u64::<LittleEndian>(idx);
        hmac_context.update(buf.get_ref());
        hmac_context.update(&hmac_key_base);
        let hmac_key = hmac_context.finish().as_ref().to_owned();
        buf.write_u32::<LittleEndian>(block_size);
        buf.write(&block);
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key);
        println!("Verifying HMAC");
        hmac::verify(&hmac_key, buf.get_ref(), &hmac_tag).unwrap();
    };

    Ok(())
}
