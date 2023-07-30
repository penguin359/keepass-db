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
    //assert_eq!(MemoryProtection::parse(&mut reader).expect("No error"), Some(String::from("  This is  Test  of it 4   ")));
    let mp = MemoryProtection::parse(&mut reader, OwnedName::local("MemoryProtection"), vec![]).expect("No error");
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
    let mp = MemoryProtection::parse(&mut reader, OwnedName::local("MemoryProtection"), vec![]).expect("No error");
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
    let mp = MemoryProtection::parse(&mut reader, OwnedName::local("MemoryProtection"), vec![]).expect("No error");
    end_document(reader);
    assert_eq!(mp.protect_notes, true);
    assert_eq!(mp.protect_password, true);
    assert_eq!(mp.protect_title, true);
    assert_eq!(mp.protect_url, true);
    assert_eq!(mp.protect_user_name, true);
}

#[test]
fn test_encode_memory_protection_all() {
    let buffer = vec![];
    let mut writer = xml::writer::EventWriter::new(buffer);
    writer.write(xml::writer::XmlEvent::start_element("MemoryProtection")).expect("Success!");
    MemoryProtection::serialize2(&mut writer, MemoryProtection {
        protect_notes: true,
        protect_password: true,
        protect_title: true,
        protect_url: true,
        protect_user_name: true,
    }).expect("No error");
    writer.write(xml::writer::XmlEvent::end_element()).expect("Success!");
    let buffer = writer.into_inner();
    let mut reader = ParserConfig::new()
        .create_reader(Cursor::new(buffer));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {},
        _ => { panic!("Missing document start"); },
    };
    let root = "MemoryProtection";
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => { assert_eq!(name.local_name, root); },
        _ => { panic!("Missing root element start"); },
    }
    let mp = MemoryProtection::parse(&mut reader, OwnedName::local("MemoryProtection"), vec![]).expect("No error");
    //end_document(reader);
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
    let meta = Meta::parse(&mut reader, OwnedName::local("Meta"), vec![]).expect("No error");
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
    let meta = Meta::parse(&mut reader, OwnedName::local("Meta"), vec![]).expect("No error");
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
fn test_decode_entry_empty() {
    let mut reader = start_document("<Entry/>", "Entry");
    let entry = Entry::parse(&mut reader, OwnedName::local("Entry"), vec![]).expect("No error");
    end_document(reader);
    assert_eq!(entry.uuid, ""); //Uuid::nil());
    assert_eq!(entry.icon_id, 0);
    assert_eq!(entry.history.len(), 0);
}

#[test]
fn test_decode_entry_filled() {
    let mut reader = start_document(r#"
    <Entry>
            <UUID>g9fGIDnSR8WvjPBJ/L4juA==</UUID>
            <IconID>12</IconID>
            <History>
                    <Entry>
                        <UUID>g9fGIDnSR8WvjPBJ/L4juA==</UUID>
                        <IconID>7</IconID>
                    </Entry>
                    <Entry>
                        <UUID>g9fGIDnSR8WvjPBJ/L4juA==</UUID>
                        <IconID>25</IconID>
                    </Entry>
            </History>
    </Entry>
    "#, "Entry");
    let entry = Entry::parse(&mut reader, OwnedName::local("Entry"), vec![]).expect("No error");
    end_document(reader);
    let _expected_uuid = uuid!("83d7c620-39d2-47c5-af8c-f049fcbe23b8");
    assert_eq!(entry.uuid, "g9fGIDnSR8WvjPBJ/L4juA==");
    assert_eq!(entry.icon_id, 12);
    assert_eq!(entry.history.len(), 2);
    assert_eq!(entry.history[0].uuid, "g9fGIDnSR8WvjPBJ/L4juA==");
    assert_eq!(entry.history[0].icon_id, 7);
    assert_eq!(entry.history[1].uuid, "g9fGIDnSR8WvjPBJ/L4juA==");
    assert_eq!(entry.history[1].icon_id, 25);
}

#[test]
fn test_encode_entry_filled() {
    let mut reader = start_document(r#"
    <Entry>
            <UUID>g9fGIDnSR8WvjPBJ/L4juA==</UUID>
            <IconID>12</IconID>
            <History>
                    <Entry>
                        <UUID>g9fGIDnSR8WvjPBJ/L4juA==</UUID>
                        <IconID>7</IconID>
                    </Entry>
                    <Entry>
                        <UUID>g9fGIDnSR8WvjPBJ/L4juA==</UUID>
                        <IconID>25</IconID>
                    </Entry>
            </History>
    </Entry>
    "#, "Entry");
    let actual = Entry::parse(&mut reader, OwnedName::local("Entry"), vec![]).expect("No error");
    end_document(reader);

    let buffer = vec![];
    let mut writer = xml::writer::EventWriter::new(buffer);
    writer.write(xml::writer::XmlEvent::start_element("Entry")).expect("Success!");
    Entry::serialize2(&mut writer, actual).expect("No error");
//    Entry::serialize2(&mut writer, Entry {
//        protect_notes: true,
//        protect_password: true,
//        protect_title: true,
//        protect_url: true,
//        protect_user_name: true,
//    }).expect("No error");
    writer.write(xml::writer::XmlEvent::end_element()).expect("Success!");
    let buffer = writer.into_inner();
    let mut reader = ParserConfig::new()
        .create_reader(Cursor::new(buffer));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {},
        _ => { panic!("Missing document start"); },
    };
    let root = "Entry";
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => { assert_eq!(name.local_name, root); },
        _ => { panic!("Missing root element start"); },
    }
    let entry = Entry::parse(&mut reader, OwnedName::local("Entry"), vec![]).expect("No error");

    assert_eq!(entry.uuid, "g9fGIDnSR8WvjPBJ/L4juA==");
    assert_eq!(entry.icon_id, 12);
    assert_eq!(entry.history.len(), 2);
    assert_eq!(entry.history[0].uuid, "g9fGIDnSR8WvjPBJ/L4juA==");
    assert_eq!(entry.history[0].icon_id, 7);
    assert_eq!(entry.history[1].uuid, "g9fGIDnSR8WvjPBJ/L4juA==");
    assert_eq!(entry.history[1].icon_id, 25);
}

#[test]
fn test_decode_document_empty() {
    let mut reader = start_document("<KeePassFile/>", "KeePassFile");
    let document = KeePassFile::parse(&mut reader, OwnedName::local("KeePassFile"), vec![]).expect("No error");
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
fn test_encode_document_empty() {
    let expected = KeePassFile::default();
    let buffer = vec![];
    let mut writer = xml::writer::EventWriter::new(buffer);
    writer.write(xml::writer::XmlEvent::start_element("KeePassFile")).expect("Success!");
    KeePassFile::serialize2(&mut writer, expected).expect("No error");
    writer.write(xml::writer::XmlEvent::end_element()).expect("Success!");
    let buffer = writer.into_inner();
    let mut reader = ParserConfig::new()
        .create_reader(Cursor::new(buffer));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {},
        _ => { panic!("Missing document start"); },
    };
    let root = "KeePassFile";
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => { assert_eq!(name.local_name, root); },
        _ => { panic!("Missing root element start"); },
    }
    let actual = KeePassFile::parse(&mut reader, OwnedName::local("KeePassFile"), vec![]).expect("No error");
    assert_eq!(actual.meta.database_name, "");
    assert_eq!(actual.meta.default_user_name, "");
    assert_eq!(actual.meta.memory_protection.protect_notes, false);
    assert_eq!(actual.meta.memory_protection.protect_password, false);
    assert_eq!(actual.meta.memory_protection.protect_title, false);
    assert_eq!(actual.meta.memory_protection.protect_url, false);
    assert_eq!(actual.meta.memory_protection.protect_user_name, false);
}

#[test]
fn test_decode_document_filled() {
    // let mut file = File::open("dummy.xml").expect("Missing test data dummy.xml");
    // let mut contents = Vec::new();
    // let mut Cursor::new(contents);
    // file.read_to_end(&mut contents);
    let contents = include_str!("../testdata/dummy.xml");
    let mut reader = start_document(contents, "KeePassFile");
    let document = KeePassFile::parse(&mut reader, OwnedName::local("KeePassFile"), vec![]).expect("No error");
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
fn test_encode_document_filled() {
    let mut expected = KeePassFile::default();
    expected.meta.database_name = "Dummy".to_string();
    expected.meta.default_user_name = "Someone".to_string();
    expected.meta.memory_protection.protect_notes = true;
    expected.meta.memory_protection.protect_password = true;
    expected.meta.memory_protection.protect_title = true;
    expected.meta.memory_protection.protect_url = true;
    expected.meta.memory_protection.protect_user_name = true;
    let buffer = vec![];
    let mut writer = xml::writer::EventWriter::new(buffer);
    writer.write(xml::writer::XmlEvent::start_element("KeePassFile")).expect("Success!");
    KeePassFile::serialize2(&mut writer, expected).expect("No error");
    writer.write(xml::writer::XmlEvent::end_element()).expect("Success!");
    let buffer = writer.into_inner();
    let mut reader = ParserConfig::new()
        .create_reader(Cursor::new(buffer));
    match reader.next().unwrap() {
        XmlEvent::StartDocument { .. } => {},
        _ => { panic!("Missing document start"); },
    };
    let root = "KeePassFile";
    match reader.next().unwrap() {
        XmlEvent::StartElement { name, .. } => { assert_eq!(name.local_name, root); },
        _ => { panic!("Missing root element start"); },
    }
    let actual = KeePassFile::parse(&mut reader, OwnedName::local("KeePassFile"), vec![]).expect("No error");
    assert_eq!(actual.meta.database_name, "Dummy");
    assert_eq!(actual.meta.default_user_name, "Someone");
    assert_eq!(actual.meta.memory_protection.protect_notes, true);
    assert_eq!(actual.meta.memory_protection.protect_password, true);
    assert_eq!(actual.meta.memory_protection.protect_title, true);
    assert_eq!(actual.meta.memory_protection.protect_url, true);
    assert_eq!(actual.meta.memory_protection.protect_user_name, true);
}

#[test]
fn test_decode_document_kdbx41() {
    // let mut file = File::open("dummy.xml").expect("Missing test data dummy.xml");
    // let mut contents = Vec::new();
    // let mut Cursor::new(contents);
    // file.read_to_end(&mut contents);
    let contents = include_str!("../testdata/dummy-kdbx41.xml");
    let mut reader = start_document(contents, "KeePassFile");
    let document = KeePassFile::parse(&mut reader, OwnedName::local("KeePassFile"), vec![]).expect("No error");
    end_document(reader);
    assert_eq!(document.meta.generator, "KeePass");
    assert_eq!(document.meta.database_name, "MyDatabase");
    assert_eq!(document.meta.database_name_changed, Some(DateTime::parse_from_rfc3339("2021-07-30T21:33:09+00:00").unwrap().with_timezone(&Utc)));
    assert_eq!(document.meta.database_description, "A KDBX 4.1 Database from KeePass 2.48.1.");
    assert_eq!(document.meta.database_description_changed, Some(DateTime::parse_from_rfc3339("2021-07-30T21:33:09+00:00").unwrap().with_timezone(&Utc)));
    assert_eq!(document.meta.default_user_name, "user");
    assert_eq!(document.meta.default_user_name_changed, Some(DateTime::parse_from_rfc3339("2021-07-30T21:33:09+00:00").unwrap().with_timezone(&Utc)));
    assert_eq!(document.meta.maintenance_history_days, 365);
    //assert_eq!(document.meta.color, Color::rgb(0xFF, 0x00, 0x3F));
    assert_eq!(document.meta.master_key_changed, Some(DateTime::parse_from_rfc3339("2021-07-31T00:02:45+00:00").unwrap().with_timezone(&Utc)));
    assert_eq!(document.meta.master_key_change_rec, 182);
    assert_eq!(document.meta.master_key_change_force, 365);
    assert_eq!(document.meta.memory_protection.protect_notes, false);
    assert_eq!(document.meta.memory_protection.protect_password, true);
    assert_eq!(document.meta.memory_protection.protect_title, false);
    assert_eq!(document.meta.memory_protection.protect_url, false);
    assert_eq!(document.meta.memory_protection.protect_user_name, false);
    assert_eq!(document.meta.settings_changed, Some(DateTime::parse_from_rfc3339("2021-07-31T00:03:06+00:00").unwrap().with_timezone(&Utc)));
    assert_eq!(document.meta.custom_data.len(), 0, "Correct number of custom data fields");
    // <CustomIcons>
    //     <Icon>
    //         <UUID>abfkJtfYxkaUtH41POXBww==</UUID>
    //         <Data>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</Data>
    //     </Icon>
    // </CustomIcons>
    // <RecycleBinEnabled>True</RecycleBinEnabled>
    // <RecycleBinUUID>jhrLg94DAkieJE8L64Mhsw==</RecycleBinUUID>
    // <RecycleBinChanged>lmaW2A4AAAA=</RecycleBinChanged>
    // <EntryTemplatesGroup>orPZQak4Aku0L67SCKGjOA==</EntryTemplatesGroup>
    // <EntryTemplatesGroupChanged>YXWW2A4AAAA=</EntryTemplatesGroupChanged>
    // <HistoryMaxItems>10</HistoryMaxItems>
    // <HistoryMaxSize>6291456</HistoryMaxSize>
    // <LastSelectedGroup>L/aVHMsHiESAi+PBE3bfuQ==</LastSelectedGroup>
    // <LastTopVisibleGroup>YROF9wRy0EylaPcWGFS+zQ==</LastTopVisibleGroup>
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
    let document = KeePassFile::parse(&mut reader, OwnedName::local("KeePassFile"), vec![]).expect("No error");
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

#[test]
fn test_decode_document_filled_group() {
    let contents = include_str!("../testdata/dummy.xml");
    let mut reader = start_document(contents, "KeePassFile");
    let document = KeePassFile::parse(&mut reader, OwnedName::local("KeePassFile"), vec![]).expect("No error");
    end_document(reader);
    assert_eq!(document.root.len(), 1);
    assert_eq!(document.root[0].entry.len(), 0);
    let group = &document.root[0];
    let expected_uuid = Uuid::parse_str("5a1c21b4-b663-4efb-ba79-9dea57a393eb").unwrap();
    assert_eq!(group.uuid, expected_uuid);
    assert_eq!(group.name, "Root");
    assert_eq!(group.notes, "");
    assert_eq!(group.icon_id, 48);
    assert_eq!(group.times.last_modification_time, DateTime::parse_from_rfc3339("2019-12-20T01:24:29+00:00").unwrap());
    assert_eq!(group.times.creation_time, DateTime::parse_from_rfc3339("2019-12-20T01:24:29+00:00").unwrap());
    assert_eq!(group.times.last_access_time, DateTime::parse_from_rfc3339("2019-12-20T01:24:29+00:00").unwrap());
    assert_eq!(group.times.expiry_time, DateTime::parse_from_rfc3339("2019-12-20T01:24:29+00:00").unwrap());
    assert_eq!(group.times.expires, false);
    assert_eq!(group.times.usage_count, 0);
    assert_eq!(group.times.location_changed, DateTime::parse_from_rfc3339("2019-12-20T01:24:29+00:00").unwrap());
    assert_eq!(group.is_expanded, true);
    //<DefaultAutoTypeSequence/>
    //<EnableAutoType>null</EnableAutoType>
    //<EnableSearching>null</EnableSearching>
    let expected_uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();
    assert_eq!(group.last_top_visible_entry, expected_uuid);
}

#[test]
fn test_block_writer() {
    let test_string = [
        "This is a t",
        "est of the block writer an",
        "d reader code to verify that it created the",
        " appropria",
        "te set of hmac keys and validates.",
        "",
    ];
    let mut rng = rand::thread_rng();
    let key = rng.gen::<[u8; 32]>();
    let mut buf = Vec::new();
    {
        let cursor = Cursor::new(&mut buf);
        eprintln!("HMAC Test Key: {:0x?}", &key);
        let mut writer = BlockWriter::new(&key, cursor);
        for string in test_string {
            writer.write_all(string.as_bytes()).unwrap();
            writer.flush().unwrap();
        }
    }
    //let expected = test_string.chain(["a".to_string()].iter()).join("");
    let expected = test_string.join("");
    eprintln!("Block output: {}", String::from_utf8_lossy(&buf));
    assert_eq!(buf.len(), expected.len() + test_string.len() * (32 + 4));
    let cursor = Cursor::new(&mut buf);
    let mut reader = BlockReader::new(&key, cursor);
    let mut actual = Vec::new();
    assert_eq!(reader.read_to_end(&mut actual).unwrap(), actual.len());
    assert_eq!(expected, String::from_utf8_lossy(&actual));
}

#[test]
fn test_crypto_writer() {
    let test_string = [
        "This is a t",
        "est of the block writer an",
        "d reader code to verify that it created the",
        " appropria",
        "te set of hmac keys and validates.",
        "",
    ];
    let cipher = Cipher::aes_256_cbc();
    let mut rng = rand::thread_rng();
    let key = rng.gen::<[u8; 32]>();
    let iv = rng.gen::<[u8; 16]>();
    let mut buf = Vec::new();
    {
        let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
        eprintln!("AES Test Key: {:0x?}", &key);
        let mut writer = Crypto::new(cipher, &key, Some(&iv), cursor).expect("Failed to create crypto");
        for string in test_string {
            writer.write_all(string.as_bytes()).unwrap();
            writer.flush().unwrap();
        }
    }
    //let expected = test_string.chain(["a".to_string()].iter()).join("");
    let expected = test_string.join("");
    eprintln!("Block output: {}", String::from_utf8_lossy(&buf));
    assert_eq!(buf.len(), (expected.len() + 15)/16*16);
    let actual = decrypt(cipher, &key, Some(&iv), &buf).expect("Failed to decrypt");
    // let cursor = Cursor::new(&mut buf);
    // let mut reader = BlockReader::new(&key, cursor);
    // let mut actual = Vec::new();
    // assert_eq!(reader.read_to_end(&mut actual).unwrap(), actual.len());
    assert_eq!(expected, String::from_utf8_lossy(&actual));
}

#[test]
fn test_save_tlvs_ver3() {
    let mut buf = Cursor::new(Vec::new());
    let mut map = BTreeMap::new();
    map.insert(3, vec![vec![9u8, 8u8, 7u8]]);
    map.insert(1, vec![vec![0u8, 1u8, 2u8, 3u8]]);
    map.insert(2, vec![vec![3u8, 4u8], vec![5u8, 6u8]]);
    let expected = vec![
        1u8, 4, 0, 0, 1, 2, 3,  // TLV 1 = [0,1,2,3]
        2, 2, 0, 3, 4,  // TLV 2 = [3, 4]
        2, 2, 0, 5, 6,  // TLV 2 = [5, 6]
        3, 3, 0, 9, 8, 7,  // TLV 3 =  [9, 8, 7]
        0, 0, 0,  // TLV END
    ];
    let actual = save_tlvs(&mut buf, &map, 3).expect("Failed to write tlvs");
    assert_eq!(expected, actual);
    assert_eq!(expected, buf.into_inner());
}

#[test]
fn test_load_tlvs_ver3() {
    let mut buf = Cursor::new(vec![
        2, 2, 0, 3, 4,  // TLV 2 = [3, 4]
        3, 3, 0, 9, 8, 7,  // TLV 3 =  [9, 8, 7]
        1u8, 4, 0, 0, 1, 2, 3,  // TLV 1 = [0,1,2,3]
        2, 2, 0, 5, 6,  // TLV 2 = [5, 6]
        0, 0, 0,  // TLV END
    ]);
    let (actual, bytes) = load_tlvs(&mut buf, 3).expect("Failed to read tlvs");
    assert_eq!(bytes, buf.into_inner());
    assert_eq!(actual.len(), 3);
    assert_eq!(actual[&1].len(), 1);
    assert_eq!(actual[&2].len(), 2);
    assert_eq!(actual[&3].len(), 1);
    assert_eq!(actual[&1], vec![vec![0u8, 1u8, 2u8, 3u8]]);
    assert_eq!(actual[&2], vec![vec![3u8, 4u8], vec![5u8, 6u8]]);
    assert_eq!(actual[&3], vec![vec![9u8, 8u8, 7u8]]);
}

#[test]
fn test_save_tlvs_ver4() {
    let mut buf = Cursor::new(Vec::new());
    let mut map = BTreeMap::new();
    map.insert(3, vec![vec![9u8, 8u8, 7u8]]);
    map.insert(1, vec![vec![0u8, 1u8, 2u8, 3u8]]);
    map.insert(2, vec![vec![3u8, 4u8], vec![5u8, 6u8]]);
    let expected = vec![
        1u8, 4, 0, 0, 0, 0, 1, 2, 3,  // TLV 1 = [0,1,2,3]
        2, 2, 0, 0, 0, 3, 4,  // TLV 2 = [3, 4]
        2, 2, 0, 0, 0, 5, 6,  // TLV 2 = [5, 6]
        3, 3, 0, 0, 0, 9, 8, 7,  // TLV 3 =  [9, 8, 7]
        0, 0, 0, 0, 0,  // TLV END
    ];
    let actual = save_tlvs(&mut buf, &map, 4).expect("Failed to write tlvs");
    assert_eq!(expected, actual);
    assert_eq!(expected, buf.into_inner());
}

#[test]
fn test_load_tlvs_ver4() {
    let mut buf = Cursor::new(vec![
        2, 2, 0, 0, 0, 3, 4,  // TLV 2 = [3, 4]
        3, 3, 0, 0, 0, 9, 8, 7,  // TLV 3 =  [9, 8, 7]
        1u8, 4, 0, 0, 0, 0, 1, 2, 3,  // TLV 1 = [0,1,2,3]
        2, 2, 0, 0, 0, 5, 6,  // TLV 2 = [5, 6]
        0, 0, 0, 0, 0,  // TLV END
    ]);
    let (actual, bytes) = load_tlvs(&mut buf, 4).expect("Failed to read tlvs");
    assert_eq!(bytes, buf.into_inner());
    assert_eq!(actual.len(), 3);
    assert_eq!(actual[&1].len(), 1);
    assert_eq!(actual[&2].len(), 2);
    assert_eq!(actual[&3].len(), 1);
    assert_eq!(actual[&1], vec![vec![0u8, 1u8, 2u8, 3u8]]);
    assert_eq!(actual[&2], vec![vec![3u8, 4u8], vec![5u8, 6u8]]);
    assert_eq!(actual[&3], vec![vec![9u8, 8u8, 7u8]]);
}
