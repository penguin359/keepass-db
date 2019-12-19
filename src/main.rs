extern crate byteorder;
extern crate uuid;
extern crate ring;

use std::io::Cursor;
use std::env;
use std::process;
use std::fs::File;
use std::io::{self, SeekFrom};
use std::io::prelude::*;
use std::collections::HashMap;

use byteorder::{LittleEndian, ReadBytesExt};
use uuid::{Builder, Uuid};
use ring::digest::{Context, Digest, SHA256};

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
    let encrption_iv = &tlvs[&7u8];
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
    loop {
        let item_type = c.read_u8()?;
        if item_type == 0 {
            break;
        }
        let item_key_len = c.read_u32::<LittleEndian>()?;
        let mut item_key = vec![0; item_key_len as usize];
        c.read_exact(&mut item_key);
        let item_key_str = String::from_utf8_lossy(&item_key);
        let item_value_len = c.read_u32::<LittleEndian>()?;
        let mut item_value = vec![0; item_value_len as usize];
        c.read_exact(&mut item_value);
        println!("K: {}, V: {:?}", item_key_str, item_value);
    }

    let mut context = Context::new(&SHA256);
    let digest = context.finish();
    println!("{:?}", digest);

    let mut context = Context::new(&SHA256);
    let header_start = 0;
    let pos = file.seek(SeekFrom::Current(0))?;
    file.seek(SeekFrom::Start(header_start))?;
    let mut header = vec![0; (pos-header_start) as usize];
    file.read_exact(&mut header)?;
    context.update(&header);
    let digest = context.finish();
    println!("{:?}", digest);
    let mut expected_hash = [0; 32];
    file.read_exact(&mut expected_hash)?;
    if digest.as_ref() != expected_hash {
        writeln!(stderr, "Possible header corruption\n")?;
        process::exit(1);
    }

    Ok(())
}
