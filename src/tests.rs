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

//const ARGON2_HASH : &str = "4eb4d1f66ae3c88d85445fb49ae7c4a8fd51eeaa132c53cb8b37610f02569371";

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
#[ignore]
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
#[ignore]
fn test_argon2_kdf_defaults() {
    assert!(false);
}

#[test]
#[ignore]
fn test_argon2_kdf_secret_and_associative() {
    assert!(false);
}

//use super::*;

#[test]
fn test_decoding_empty_document() {
    let content = "";
    let mut reader = ParserConfig::new()
        .create_reader(Cursor::new(content));
    let event = reader.next();
    assert!(event.is_err());
}

#[test]
fn test_decoding_minimal_document() {
    let content = "<root/>";
    let mut reader = ParserConfig::new()
        .create_reader(Cursor::new(content));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {},
        _ => { panic!("Missing document start"); },
    }
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => { assert_eq!(name.local_name, "root"); },
        _ => { panic!("Missing root element start"); },
    }
    match reader.next().unwrap() {
        XmlEvent::EndElement { name, .. } => { assert_eq!(name.local_name, "root"); },
        _ => { panic!("Missing root element end"); },
    }
    match reader.next().unwrap() {
        XmlEvent::EndDocument => {},
        _ => { panic!("Missing document end"); },
    }
}

#[test]
fn test_consume_minimal_document() {
    let content = "<root/>";
    let mut reader = ParserConfig::new()
        .create_reader(Cursor::new(content));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {},
        _ => { panic!("Missing document start"); },
    }
    let element = match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => name,
        _ => { panic!("Missing document element"); },
    };
    consume_element(&mut reader, element, vec![]).expect("Failed to consume");
    match reader.next().unwrap() {
        XmlEvent::EndDocument => {},
        _ => { panic!("Missing document end"); },
    }
}

#[test]
fn test_consume_nested_document() {
    let content = "<root>  <consumed>   <child1>  <!-- Comment --> <grandchild/>Test</child1> <child2>More</child2></consumed> </root>";
    let mut reader = ParserConfig::new()
        .create_reader(Cursor::new(content));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {},
        _ => { panic!("Missing document start"); },
    };
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => { assert_eq!(name.local_name, "root"); },
        _ => { panic!("Missing root element start"); },
    };
    match reader.next().unwrap() {
        XmlEvent::Whitespace(_) => {},
        _ => { panic!("Missing whitespace"); },
    };
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => { assert_eq!(name.local_name, "consumed"); },
        _ => { panic!("Missing consumed element start"); },
    };
    consume_element(&mut reader, OwnedName::local("consumed"), vec![]).expect("Failed to consume");
    match reader.next().unwrap() {
        XmlEvent::Whitespace(_) => {},
        _ => { panic!("Missing whitespace"); },
    };
    match reader.next().unwrap() {
        XmlEvent::EndElement { name, .. } => { assert_eq!(name.local_name, "root"); },
        _ => { panic!("Missing root element end"); },
    };
    match reader.next().unwrap() {
        XmlEvent::EndDocument => {},
        _ => { panic!("Missing document end"); },
    };
}

#[test]
fn test_find_next_element_document() {
    let content = "<root>  <consumed>   <child1>  <!-- Comment --> <grandchild/>Test</child1> <child2>More</child2></consumed> </root>";
    let mut reader = ParserConfig::new()
        .create_reader(Cursor::new(content));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {},
        _ => { panic!("Missing document start"); },
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::StartElement { name, .. } => { assert_eq!(name.local_name, "root", "Need root element"); },
        _ => { panic!("Missing root element start"); },
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::StartElement { name, .. } => { assert_eq!(name.local_name, "consumed"); },
        _ => { panic!("Missing consumed element start"); },
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::StartElement { name, .. } => { assert_eq!(name.local_name, "child1"); },
        _ => { panic!("Missing child1 element start"); },
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::StartElement { name, .. } => { assert_eq!(name.local_name, "grandchild"); },
        _ => { panic!("Missing grandchild element start"); },
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::EndElement { name, .. } => { assert_eq!(name.local_name, "grandchild"); },
        _ => { panic!("Missing grandchild element end"); },
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::EndElement { name, .. } => { assert_eq!(name.local_name, "child1"); },
        _ => { panic!("Missing child1 element end"); },
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::StartElement { name, .. } => { assert_eq!(name.local_name, "child2"); },
        _ => { panic!("Missing child2 element start"); },
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::EndElement { name, .. } => { assert_eq!(name.local_name, "child2"); },
        _ => { panic!("Missing child2 element end"); },
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::EndElement { name, .. } => { assert_eq!(name.local_name, "consumed"); },
        _ => { panic!("Missing root element end"); },
    };
    match find_next_element(&mut reader).expect("Valid element") {
        ElementEvent::EndElement { name, .. } => { assert_eq!(name.local_name, "root"); },
        _ => { panic!("Missing root element end"); },
    };
    match reader.next().unwrap() {
        XmlEvent::EndDocument => {},
        _ => { panic!("Missing document end"); },
    };
}

fn start_document(contents: &'static str, root: &str) -> EventReader<Cursor<&'static str>> {
    let mut reader = ParserConfig::new()
        .create_reader(Cursor::new(contents));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {},
        _ => { panic!("Missing document start"); },
    };
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => { assert_eq!(name.local_name, root); },
        _ => { panic!("Missing root element start"); },
    }
    return reader;
}

fn end_document(mut reader: EventReader<Cursor<&'static str>>) {
    match reader.next().unwrap() {
        XmlEvent::EndDocument => {},
        _ => { panic!("Missing document end"); },
    };
}

#[test]
fn test_decoding_optional_empty_string() {
    let mut reader = start_document("<root/>", "root");
    assert_eq!(decode_optional_string(&mut reader, OwnedName::local("root"), vec![]).expect("No error"),
        None);
    end_document(reader);
}

#[test]
fn test_decoding_optional_basic_string() {
    let mut reader = start_document("<root>  This is a test of it 1   </root>", "root");
    assert_eq!(decode_optional_string(&mut reader, OwnedName::local("root"), vec![]).expect("No error"),
        Some(String::from("  This is a test of it 1   ")));
    end_document(reader);
}

#[test]
fn test_decoding_optional_whitespace_string() {
    let mut reader = start_document("<root>     </root>", "root");
    assert_eq!(decode_optional_string(&mut reader, OwnedName::local("root"), vec![]).expect("No error"),
        Some(String::from("     ")));
    end_document(reader);
}

#[test]
fn test_decoding_optional_cdata_string() {
    let mut reader = start_document("<root><![CDATA[This is a test of it 3]]></root>", "root");
    assert_eq!(decode_optional_string(&mut reader, OwnedName::local("root"), vec![]).expect("No error"),
        Some(String::from("This is a test of it 3")));
    end_document(reader);
}

#[test]
fn test_decoding_optional_full_string() {
    let mut reader = start_document("<root>  This is <![CDATA[ Test ]]> of it 4   </root>", "root");
    assert_eq!(decode_optional_string(&mut reader, OwnedName::local("root"), vec![]).expect("No error"),
        Some(String::from("  This is  Test  of it 4   ")));
    end_document(reader);
}

#[test]
fn test_decode_memory_protection_empty() {
    let mut reader = start_document("<MemoryProtection/>", "MemoryProtection");
    //assert_eq!(decode_memory_protection(&mut reader).expect("No error"), Some(String::from("  This is  Test  of it 4   ")));
    let mp = decode_memory_protection(&mut reader, OwnedName::local("MemoryProtection"), vec![]).expect("No error");
    end_document(reader);
    assert_eq!(mp.protect_notes, false);
    assert_eq!(mp.protect_password, false);
    assert_eq!(mp.protect_title, false);
    assert_eq!(mp.protect_url, false);
    assert_eq!(mp.protect_user_name, false);
}

#[test]
fn test_decode_memory_protection_some() {
    let mut reader = start_document(r#"		<MemoryProtection>
    <ProtectTitle>False</ProtectTitle>
    <ProtectUserName>False</ProtectUserName>
    <ProtectPassword>True</ProtectPassword>
    <ProtectURL>False</ProtectURL>
    <ProtectNotes>False</ProtectNotes>
</MemoryProtection>
"#, "MemoryProtection");
    let mp = decode_memory_protection(&mut reader, OwnedName::local("MemoryProtection"), vec![]).expect("No error");
    end_document(reader);
    assert_eq!(mp.protect_notes, false);
    assert_eq!(mp.protect_password, true);
    assert_eq!(mp.protect_title, false);
    assert_eq!(mp.protect_url, false);
    assert_eq!(mp.protect_user_name, false);
}

#[test]
fn test_decode_memory_protection_all() {
    let mut reader = start_document(r#"		<MemoryProtection>
    <ProtectTitle>True</ProtectTitle>
    <ProtectUserName>True</ProtectUserName>
    <ProtectPassword>True</ProtectPassword>
    <ProtectURL>True</ProtectURL>
    <ProtectNotes>True</ProtectNotes>
</MemoryProtection>
"#, "MemoryProtection");
    let mp = decode_memory_protection(&mut reader, OwnedName::local("MemoryProtection"), vec![]).expect("No error");
    end_document(reader);
    assert_eq!(mp.protect_notes, true);
    assert_eq!(mp.protect_password, true);
    assert_eq!(mp.protect_title, true);
    assert_eq!(mp.protect_url, true);
    assert_eq!(mp.protect_user_name, true);
}

#[test]
fn test_decode_item_empty() {
    let mut reader = start_document("<Item/>", "Item");
    let item = decode_item(&mut reader, OwnedName::local("Item"), vec![]).expect("No error");
    end_document(reader);
    assert_eq!(item.0, "");
    assert_eq!(item.1, "");
}

#[test]
fn test_decode_item_pair() {
    let mut reader = start_document("  <Item>  <Value>mexican</Value>  <Key>food</Key>   </Item>  ", "Item");
    let result = decode_item(&mut reader, OwnedName::local("Item"), vec![]);
    if result.is_err() {
        assert!(false, "Decoding returned error: {:?}", result.unwrap_err());
    }
    let item = result.unwrap();
    end_document(reader);
    assert_eq!(item.0, "food");
    assert_eq!(item.1, "mexican");
}

#[test]
fn test_decode_custom_data_empty() {
    let mut reader = start_document("<CustomData/>", "CustomData");
    let custom_data = decode_custom_data(&mut reader, OwnedName::local("CustomData"), vec![]).expect("No error");
    end_document(reader);
    assert_eq!(custom_data.len(), 0);
}

#[test]
fn test_decode_custom_data_simple() {
    let mut reader = start_document("<CustomData><Item><Key>one</Key><Value>1</Value></Item></CustomData>", "CustomData");
    let custom_data = decode_custom_data(&mut reader, OwnedName::local("CustomData"), vec![]).expect("No error");
    end_document(reader);
    assert_eq!(custom_data.len(), 1);
    assert!(custom_data.contains_key("one"), "Has appropriate key");
    assert_eq!(custom_data["one"], "1");
}

#[test]
fn test_decode_meta_empty() {
    let mut reader = start_document("<Meta/>", "Meta");
    let meta = decode_meta(&mut reader).expect("No error");
    end_document(reader);
    assert_eq!(meta.database_name, "");
    assert_eq!(meta.default_user_name, "");
    assert_eq!(meta.memory_protection.protect_notes, false);
    assert_eq!(meta.memory_protection.protect_password, false);
    assert_eq!(meta.memory_protection.protect_title, false);
    assert_eq!(meta.memory_protection.protect_url, false);
    assert_eq!(meta.memory_protection.protect_user_name, false);
}

#[test]
fn test_decode_meta_filled() {
    let mut reader = start_document(r#"
    <Meta>
    <Generator>KeePassXC</Generator>
    <DatabaseName>Dummy</DatabaseName>
    <DatabaseNameChanged>3BmO1Q4AAAA=</DatabaseNameChanged>
    <DatabaseDescription>Empty KDBX 4.x Database</DatabaseDescription>
    <DatabaseDescriptionChanged>3BmO1Q4AAAA=</DatabaseDescriptionChanged>
    <DefaultUserName>someone</DefaultUserName>
    <DefaultUserNameChanged>I6fN1Q4AAAA=</DefaultUserNameChanged>
    <MaintenanceHistoryDays>365</MaintenanceHistoryDays>
    <Color/>
    <MasterKeyChanged>4xqO1Q4AAAA=</MasterKeyChanged>
    <MasterKeyChangeRec>-1</MasterKeyChangeRec>
    <MasterKeyChangeForce>-1</MasterKeyChangeForce>
    <MemoryProtection>
        <ProtectTitle>False</ProtectTitle>
        <ProtectUserName>False</ProtectUserName>
        <ProtectPassword>True</ProtectPassword>
        <ProtectURL>False</ProtectURL>
        <ProtectNotes>False</ProtectNotes>
    </MemoryProtection>
    <CustomIcons/>
    <RecycleBinEnabled>True</RecycleBinEnabled>
    <RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>
    <RecycleBinChanged>zRmO1Q4AAAA=</RecycleBinChanged>
    <EntryTemplatesGroup>AAAAAAAAAAAAAAAAAAAAAA==</EntryTemplatesGroup>
    <EntryTemplatesGroupChanged>zRmO1Q4AAAA=</EntryTemplatesGroupChanged>
    <LastSelectedGroup>AAAAAAAAAAAAAAAAAAAAAA==</LastSelectedGroup>
    <LastTopVisibleGroup>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleGroup>
    <HistoryMaxItems>10</HistoryMaxItems>
    <HistoryMaxSize>6291456</HistoryMaxSize>
    <SettingsChanged>I6fN1Q4AAAA=</SettingsChanged>
    <CustomData>
        <Item>
            <Key>FDO_SECRETS_EXPOSED_GROUP</Key>
            <Value>{00000000-0000-0000-0000-000000000000}</Value>
        </Item>
        <Item>
            <Key>KPXC_DECRYPTION_TIME_PREFERENCE</Key>
            <Value>100</Value>
        </Item>
        <Item>
            <Key>_LAST_MODIFIED</Key>
            <Value>Thu Feb 6 06:08:06 2020 GMT</Value>
        </Item>
    </CustomData>
</Meta>
"#, "Meta");
    let meta = decode_meta(&mut reader).expect("No error");
    end_document(reader);
    assert_eq!(meta.database_name, "Dummy");
    assert_eq!(meta.default_user_name, "someone");
    assert_eq!(meta.memory_protection.protect_notes, false);
    assert_eq!(meta.memory_protection.protect_password, true);
    assert_eq!(meta.memory_protection.protect_title, false);
    assert_eq!(meta.memory_protection.protect_url, false);
    assert_eq!(meta.memory_protection.protect_user_name, false);
    assert_eq!(meta.custom_data.len(), 3, "Correct number of custom data fields");
    assert!(meta.custom_data.contains_key("KPXC_DECRYPTION_TIME_PREFERENCE"), "Missing a custom data field");
    assert_eq!(meta.custom_data["KPXC_DECRYPTION_TIME_PREFERENCE"], "100", "Custom data field has wrong value");
}

#[test]
fn test_decode_document_empty() {
    let mut reader = start_document("<KeePassFile/>", "KeePassFile");
    let document = decode_document(&mut reader).expect("No error");
    end_document(reader);
    assert_eq!(document.meta.database_name, "");
    assert_eq!(document.meta.default_user_name, "");
    assert_eq!(document.meta.memory_protection.protect_notes, false);
    assert_eq!(document.meta.memory_protection.protect_password, false);
    assert_eq!(document.meta.memory_protection.protect_title, false);
    assert_eq!(document.meta.memory_protection.protect_url, false);
    assert_eq!(document.meta.memory_protection.protect_user_name, false);
}

#[test]
fn test_decode_document_filled() {
    // let mut file = File::open("dummy.xml").expect("Missing test data dummy.xml");
    // let mut contents = Vec::new();
    // let mut Cursor::new(contents);
    // file.read_to_end(&mut contents);
    let contents = include_str!("../testdata/dummy.xml");
    let mut reader = start_document(contents, "KeePassFile");
    let document = decode_document(&mut reader).expect("No error");
    end_document(reader);
    assert_eq!(document.meta.database_name, "Dummy");
    assert_eq!(document.meta.default_user_name, "someone");
    assert_eq!(document.meta.memory_protection.protect_notes, false);
    assert_eq!(document.meta.memory_protection.protect_password, true);
    assert_eq!(document.meta.memory_protection.protect_title, false);
    assert_eq!(document.meta.memory_protection.protect_url, false);
    assert_eq!(document.meta.memory_protection.protect_user_name, false);
    assert_eq!(document.meta.custom_data.len(), 3, "Correct number of custom data fields");
    assert!(document.meta.custom_data.contains_key("KPXC_DECRYPTION_TIME_PREFERENCE"), "Missing a custom data field");
    assert_eq!(document.meta.custom_data["KPXC_DECRYPTION_TIME_PREFERENCE"], "100", "Custom data field has wrong value");
}

#[test]
fn test_decode_document_kdbx41() {
    // let mut file = File::open("dummy.xml").expect("Missing test data dummy.xml");
    // let mut contents = Vec::new();
    // let mut Cursor::new(contents);
    // file.read_to_end(&mut contents);
    let contents = include_str!("../testdata/dummy-kdbx41.xml");
    let mut reader = start_document(contents, "KeePassFile");
    let document = decode_document(&mut reader).expect("No error");
    end_document(reader);
    assert_eq!(document.meta.generator, "KeePass");
    assert_eq!(document.meta.database_name, "MyDatabase");
    assert_eq!(document.meta.default_user_name, "user");
    assert_eq!(document.meta.memory_protection.protect_notes, false);
    assert_eq!(document.meta.memory_protection.protect_password, true);
    assert_eq!(document.meta.memory_protection.protect_title, false);
    assert_eq!(document.meta.memory_protection.protect_url, false);
    assert_eq!(document.meta.memory_protection.protect_user_name, false);
    assert_eq!(document.meta.custom_data.len(), 0, "Correct number of custom data fields");
}

/*
use super::Cursor;
use super::{EventReader, XmlEvent};

#[test]
fn test_basic_document() {
    let mut cursor = Cursor::new(b"");
    let mut reader = EventReader::new(cursor);
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => (),
        _ => { panic!("Bad state"); },
    };
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => (),
        _ => { panic!("Bad state"); },
    };
}
*/

#[test]
fn test_decode_document_filled_contents() {
    let contents = include_str!("../testdata/dummy.xml");
    let mut reader = start_document(contents, "KeePassFile");
    let document = decode_document(&mut reader).expect("No error");
    end_document(reader);
    //assert_eq!(document.meta.database_name, "Dummy");
    //assert_eq!(document.meta.default_user_name, "someone");
    //assert_eq!(document.meta.memory_protection.protect_notes, false);
    //assert_eq!(document.meta.memory_protection.protect_password, true);
    //assert_eq!(document.meta.memory_protection.protect_title, false);
    //assert_eq!(document.meta.memory_protection.protect_url, false);
    //assert_eq!(document.meta.memory_protection.protect_user_name, false);
    //assert_eq!(document.meta.custom_data.len(), 3, "Correct number of custom data fields");
    //assert!(document.meta.custom_data.contains_key("KPXC_DECRYPTION_TIME_PREFERENCE"), "Missing a custom data field");
    //assert_eq!(document.meta.custom_data["KPXC_DECRYPTION_TIME_PREFERENCE"], "100", "Custom data field has wrong value");
    assert_eq!(document.root.len(), 1);
    assert_eq!(document.root[0].entry.len(), 0);
    assert_eq!(document.root[0].group.len(), 1);
    assert_eq!(document.root[0].group[0].entry.len(), 1);
    assert_eq!(document.root[0].group[0].entry[0].history.len(), 2);
    assert_eq!(document.root[0].group[0].group.len(), 2);
    assert_eq!(document.root[0].group[0].group[0].entry.len(), 1);
    assert_eq!(document.root[0].group[0].group[0].entry[0].history.len(), 2);
    assert_eq!(document.root[0].group[0].group[0].group.len(), 1);
    assert_eq!(document.root[0].group[0].group[0].group[0].entry.len(), 1);
    assert_eq!(document.root[0].group[0].group[0].group[0].entry[0].history.len(), 0);
    assert_eq!(document.root[0].group[0].group[0].group[0].group.len(), 0);
    assert_eq!(document.root[0].group[0].group[1].entry.len(), 0);
    assert_eq!(document.root[0].group[0].group[1].group.len(), 0);
}
