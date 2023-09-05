use std::collections::HashMap;
use std::io::{self, prelude::*, Cursor};
use std::process;
// use std::time::{SystemTime, UNIX_EPOCH};
use std::vec::Vec;
// use std::str;
// use std::fmt;
// use std::cell::RefCell;

use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, Local, Utc, NaiveDateTime, NaiveDate, TimeZone};
use openssl::symm::{decrypt, Cipher};
use uuid::Uuid;
use rand::Rng;
use ring::digest::{Context, SHA256, SHA512};

use crate::{make_u64, Key, unmake_u64_be};
use crate::kdf::{transform_aes_kdf, KDF_PARAM_ROUNDS, KDF_PARAM_SALT};

use super::{Group, Entry, Times, AutoType, ProtectedString, ProtectedValue, ProtectedBinary, BinaryRef, TITLE_FIELD, USER_NAME_FIELD, PASSWORD_FIELD, URL_FIELD, NOTES_FIELD};

pub struct KdbGroup {
    //<'a> {
    pub uuid: u32,
    pub parent: u32,
    pub name: String,
    pub creation_time: DateTime<Local>,
    pub modification_time: DateTime<Local>,
    pub access_time: DateTime<Local>,
    pub expiry_time: DateTime<Local>,
    pub icon: u32,
    pub flags: u32,
    //pub groups: Vec<&'a KdbGroup>,
    pub groups: Vec<u32>,
    pub entries: Vec<Uuid>,
}

impl From<KdbGroup> for Group {
    fn from(value: KdbGroup) -> Self {
        Group {
            uuid: Uuid::nil(),
            name: value.name,
            notes: "".to_string(),
            icon_id: value.icon,
            custom_icon_uuid: None,
            times: Times {
                creation_time: value.creation_time.with_timezone(&Utc),
                last_modification_time: value.modification_time.with_timezone(&Utc),
                last_access_time: value.access_time.with_timezone(&Utc),
                expiry_time: value.expiry_time.with_timezone(&Utc),
                expires: false,  // TODO Needs to be detected from value above
                usage_count: 0,
                location_changed: value.modification_time.with_timezone(&Utc),  // TODO This the best choice?
            },
            is_expanded: true,
            default_auto_type_sequence: "".to_string(),
            enable_auto_type: true,
            enable_searching: true,
            last_top_visible_entry: Uuid::nil(),
            previous_parent_group: None,
            tags: None,
            entry: vec![],
            group: vec![],
        }
    }
}

pub struct KdbEntry {
    pub uuid: Uuid,
    pub parent: u32,
    pub icon: u32,
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub creation_time: DateTime<Local>,
    pub modification_time: DateTime<Local>,
    pub access_time: DateTime<Local>,
    pub expiry_time: DateTime<Local>,
    pub binary_description: String,
    pub binary_data: Vec<u8>,
}

impl From<KdbEntry> for Entry {
    fn from(value: KdbEntry) -> Self {
        Entry {
            uuid: value.uuid,
            icon_id: value.icon,
            custom_icon_uuid: None,

            foreground_color: "".to_string(),  // Should be None
            background_color: "".to_string(),  // Should be None
            override_url: "".to_string(),
            quality_check: None,
            tags: "".to_string(),
            previous_parent_group: None,
            times: Times {
                creation_time: value.creation_time.with_timezone(&Utc),
                last_modification_time: value.modification_time.with_timezone(&Utc),
                last_access_time: value.access_time.with_timezone(&Utc),
                expiry_time: value.expiry_time.with_timezone(&Utc),
                expires: false,  // TODO Needs to be detected from value above
                usage_count: 0,
                location_changed: value.modification_time.with_timezone(&Utc),  // TODO This the best choice?
            },
            custom_data: vec![],
            string: vec![
                ProtectedString {
                    key: TITLE_FIELD.to_string(),
                    value: ProtectedValue::Unprotected(value.title),
                },
                ProtectedString {
                    key: USER_NAME_FIELD.to_string(),
                    value: ProtectedValue::Unprotected(value.username),
                },
                ProtectedString {
                    key: PASSWORD_FIELD.to_string(),
                    value: ProtectedValue::Unprotected(value.password),
                },
                ProtectedString {
                    key: URL_FIELD.to_string(),
                    value: ProtectedValue::Unprotected(value.url),
                },
                ProtectedString {
                    //key: NOTES_FIELD.to_string(),
                    key: URL_FIELD.to_string(),
                    value: ProtectedValue::Unprotected(value.notes),
                },
            ],
            binary: vec![
                ProtectedBinary {
                    key: value.binary_description,
                    value: BinaryRef(value.binary_data),
                },
            ],
            auto_type: AutoType {
                enabled: false,
                data_transfer_obfuscation: 0,
                default_sequence: None,
                association: vec![],
            },
            history: None,
        }
    }
}

pub struct KdbDatabase {
    pub groups: HashMap<u32, KdbGroup>,
    pub entries: HashMap<Uuid, KdbEntry>,
}

fn decode_string_kdb1(mut content: Vec<u8>) -> String {
    if content[content.len() - 1] != 0 {
        panic!("Need null terminator");
    }
    content.truncate(content.len() - 1);
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
    NaiveDate::from_ymd_opt(year as i32, month as u32, day as u32).map(|d| d.and_hms_opt(
        hour as u32,
        minute as u32,
        second as u32,
    )).unwrap().unwrap()
}

fn dump_group(database: &KdbDatabase, uuid: u32, depth: u16) {
    let group = database.groups.get(&uuid).unwrap();
    println!("{0:1$}>{2}", "", 2 * depth as usize, group.name);
    for child in &group.groups {
        dump_group(database, *child, depth + 1);
    }
    for child in &group.entries {
        let entry = database.entries.get(&child).unwrap();
        println!("{0:1$}  -{2}", "", 2 * depth as usize, entry.title);
    }
}

fn read_tlvs<R: Read>(file: &mut R) -> io::Result<HashMap<u16, Vec<u8>>> {
    let mut map = HashMap::new();
    loop {
        let field_type = file.read_u16::<LittleEndian>()?;
        let field_len = file.read_u32::<LittleEndian>()?;
        let mut field_content = vec![0; field_len as usize];
        file.read_exact(&mut field_content)?;
        if field_type == 0xffff {
            // TODO Check field length
            return Ok(map)
        }
        map.insert(field_type, field_content);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_tlvs() {
        let mut buf = Cursor::new(vec![
            1u8, 0,  // Type = 1
            4, 0, 0, 0,  // Length = 4
            0, 1, 2, 3,  // Value
            2, 0,  // Type = 2
            6, 0, 0, 0,  // Length = 6
            0xa, 0xb, 0xc, 0xd, 0xe, 0xf,  // Value
            0xff, 0xff,  // Type = End
            0, 0, 0, 0,  // Length = 0
        ]);
        let tlvs = read_tlvs(&mut buf).expect("Error reading TLVs");
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[&1u16], vec![0, 1, 2, 3]);
        assert_eq!(tlvs[&2u16], vec![0xa, 0xb, 0xc, 0xd, 0xe, 0xf]);
    }
}

pub fn read_kdb1_header<R: Read>(file: &mut R, key: &Key) -> io::Result<()> {
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
    println!(
        "flags: {}, version: {}, groups: {}, entries: {}, round: {:?}",
        flags, version, num_groups, num_entries, transform_round
    );

    println!("AES");

    let mut custom_data = HashMap::<String, Vec<u8>>::new();
    custom_data.insert(KDF_PARAM_SALT.to_string(), transform_seed);
    custom_data.insert(
        KDF_PARAM_ROUNDS.to_string(),
        make_u64(transform_round as u64),
    );

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

    println!(
        "MK: {}, IV: {}, CP: {}",
        master_key.len(),
        encryption_iv.len(),
        ciphertext.len()
    );
    let data = decrypt(
        Cipher::aes_256_cbc(),
        &master_key,
        Some(encryption_iv.as_ref()),
        &ciphertext,
    )
    .unwrap();

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
    // use kdb1::{KdbGroup, KdbEntry, KdbDatabase};
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
        let tlvs = read_tlvs(&mut c)?;
        for (field_type, field_content) in tlvs {
            match field_type {
                0x0000 => {
                    //readExtData(field_content);
                    let mut c = Cursor::new(&field_content);
                    println!("Ext: {:?}", read_tlvs(&mut c)?);
                    assert_eq!(c.position(), field_content.len() as u64);
                }
                0x0001 => {
                    let mut c = Cursor::new(&field_content);
                    let uuid = c.read_u32::<LittleEndian>()?;
                    group.uuid = uuid;
                    assert_eq!(c.position(), field_content.len() as u64);
                    println!("UUID: {}", uuid);
                }
                0x0002 => {
                    let name = decode_string_kdb1(field_content);
                    group.name = name;
                    println!("Name: {}", group.name);
                }
                0x0003 => {
                    let date = decode_datetime_kdb1(&field_content);
                    let datetime = Local.from_utc_datetime(&date);
                    group.creation_time = datetime;
                    println!(
                        "Creation Time: {}",
                        group.creation_time.format("%Y-%m-%d %l:%M:%S %p %Z")
                    );
                }
                0x0004 => {
                    let date = decode_datetime_kdb1(&field_content);
                    let datetime = Local.from_utc_datetime(&date);
                    group.modification_time = datetime;
                    println!(
                        "Last Modification Time: {}",
                        group.modification_time.format("%Y-%m-%d %l:%M:%S %p %Z")
                    );
                }
                0x0005 => {
                    let date = decode_datetime_kdb1(&field_content);
                    let datetime = Local.from_utc_datetime(&date);
                    group.access_time = datetime;
                    println!(
                        "Last Access Time: {}",
                        group.access_time.format("%Y-%m-%d %l:%M:%S %p %Z")
                    );
                }
                0x0006 => {
                    let date = decode_datetime_kdb1(&field_content);
                    let datetime = Local.from_utc_datetime(&date);
                    group.expiry_time = datetime;
                    println!(
                        "Expiry Time: {}",
                        group.expiry_time.format("%Y-%m-%d %l:%M:%S %p %Z")
                    );
                }
                0x0007 => {
                    let mut c = Cursor::new(&field_content);
                    let icon = c.read_u32::<LittleEndian>()?;
                    group.icon = icon;
                    assert_eq!(c.position(), field_content.len() as u64);
                    println!("Icon: {}", icon);
                }
                0x0008 => {
                    //int level = readShort(dataInput);
                    //group.setParent(computeParentGroup(lastGroup, level));
                    let mut c = Cursor::new(&field_content);
                    level = c.read_u16::<LittleEndian>()?;
                    assert_eq!(c.position(), field_content.len() as u64);
                    println!("Level: {}", level);
                }
                0x0009 => {
                    let mut c = Cursor::new(&field_content);
                    let flags = c.read_u32::<LittleEndian>()?;
                    group.flags = flags;
                    assert_eq!(c.position(), field_content.len() as u64);
                    println!("Flags: 0x{:08x}", flags);
                }
                _ => {
                    panic!("Unknown field");
                }
            };
        }
        println!("");
        //root_group.groups.push(group.uuid);
        group.parent = *groups_level.get(&level).unwrap_or(&root_group_uuid);
        all_groups
            .get_mut(&group.parent)
            .unwrap()
            .groups
            .push(group.uuid);
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
        let tlvs = read_tlvs(&mut c)?;
        for (field_type, field_content) in tlvs {
            //println!("TLV({}, {}): {:?}", field_type, field_len, field_content);
            match field_type {
                0x0000 => {
                    //readExtData(dataInput);
                    assert!(false);
                }
                0x0001 => {
                    //let mut c = Cursor::new(field_content);
                    //let uuid = c.read_u32::<LittleEndian>()?;
                    //assert_eq!(c.position(), field_len as u64);
                    let uuid = Uuid::from_slice(&field_content).unwrap();
                    entry.uuid = uuid;
                    println!("UUID: {}", entry.uuid);
                }
                0x0002 => {
                    let mut c = Cursor::new(&field_content);
                    let group_id = c.read_u32::<LittleEndian>()?;
                    entry.parent = group_id;
                    assert_eq!(c.position(), field_content.len() as u64);
                    println!("Group: {}", entry.parent);
                }
                0x0003 => {
                    let mut c = Cursor::new(&field_content);
                    let icon = c.read_u32::<LittleEndian>()?;
                    entry.icon = icon;
                    assert_eq!(c.position(), field_content.len() as u64);
                    println!("Icon: {}", entry.icon);
                }
                0x0004 => {
                    let name = decode_string_kdb1(field_content);
                    entry.title = name;
                    println!("Title: {}", entry.title);
                }
                0x0005 => {
                    let name = decode_string_kdb1(field_content);
                    entry.url = name;
                    println!("Url: {}", entry.url);
                }
                0x0006 => {
                    let name = decode_string_kdb1(field_content);
                    entry.username = name;
                    println!("Username: {}", entry.username);
                }
                0x0007 => {
                    let name = decode_string_kdb1(field_content);
                    entry.password = name;
                    println!("Password: {}", entry.password);
                }
                0x0008 => {
                    let name = decode_string_kdb1(field_content);
                    entry.notes = name;
                    println!("Notes: {}", entry.notes);
                }
                0x0009 => {
                    let date = decode_datetime_kdb1(&field_content);
                    let datetime = Local.from_utc_datetime(&date);
                    entry.creation_time = datetime;
                    println!(
                        "Creation Time: {}",
                        entry.creation_time.format("%Y-%m-%d %l:%M:%S %p %Z")
                    );
                }
                0x000a => {
                    let date = decode_datetime_kdb1(&field_content);
                    let datetime = Local.from_utc_datetime(&date);
                    entry.modification_time = datetime;
                    println!(
                        "Last Modification Time: {}",
                        entry.modification_time.format("%Y-%m-%d %l:%M:%S %p %Z")
                    );
                }
                0x000b => {
                    let date = decode_datetime_kdb1(&field_content);
                    let datetime = Local.from_utc_datetime(&date);
                    entry.access_time = datetime;
                    println!(
                        "Last Access Time: {}",
                        entry.access_time.format("%Y-%m-%d %l:%M:%S %p %Z")
                    );
                }
                0x000c => {
                    let date = decode_datetime_kdb1(&field_content);
                    let datetime = Local.from_utc_datetime(&date);
                    entry.expiry_time = datetime;
                    println!(
                        "Expiry Time: {}",
                        entry.expiry_time.format("%Y-%m-%d %l:%M:%S %p %Z")
                    );
                }
                0x000d => {
                    let name = decode_string_kdb1(field_content);
                    entry.binary_description = name;
                    println!("Binary Description: {}", entry.binary_description);
                }
                0x000e => {
                    entry.binary_data = field_content;
                    println!("Binary Data: {:#?}", entry.binary_data);
                }
                _ => {
                    panic!("Unknown field");
                }
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

    let database = KdbDatabase {
        groups: all_groups,
        entries: all_entries,
    };
    dump_group(&database, root_group_uuid, 0);

    Ok(())
}
