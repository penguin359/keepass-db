use std::convert::Into;
use std::{io::Result, path::PathBuf};

use keepass_db::{lib_main, protected_stream::CipherValue, Key};

#[test]
fn main() -> Result<()> {
    let mut key = Key::new();
    key.set_user_password("asdf");
    //let mut stream = keepass_db::protected_stream::new_stream(0, &[]).unwrap();
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("dummy-kdbx41.kdbx");
    let mut doc = lib_main(file.to_str().unwrap(), &key)?;
    let database = doc.file;
    let stream = &mut doc.cipher;
    assert_eq!(database.groups().len(), 1);
    println!("Groups:");
    for g in database.groups()[0].all_groups() {
        println!("  {title}", title=g.name());
    }
    assert_eq!(database.groups()[0].all_groups().count(), 9);
    println!("Entries:");
    for g in database.groups()[0].all_entries() {
        println!("  {title}", title=g.title().unprotect(stream).unwrap());
    }
    assert_eq!(database.groups()[0].all_entries().count(), 10);
    let full_entry = database.groups()[0].all_entries().nth(4).expect("Fifth entry is missing");
    assert_eq!(full_entry.title().unprotect(stream).unwrap(), "Full");
    assert_eq!(full_entry.username().unprotect(stream).unwrap(), "johndoe");
    assert_eq!(full_entry.password().unprotect(stream).unwrap(), "FG54PY9Z8PDTV-7C1");
    assert_eq!(full_entry.url().unprotect(stream).unwrap(), "http://www.example.org/");
    assert_eq!(full_entry.notes().unprotect(stream).unwrap(), "A complete entry as much as possible.");
    let basic_entry = database.groups()[0].all_entries().filter(|e| e.title().unprotect(stream).unwrap() == "Basic").nth(0).expect("Fifth entry is missing");
    assert_eq!(basic_entry.username().unprotect(stream).unwrap(), "user");
    let attach_entry = database.groups()[0].all_entries().filter(|e| e.title().unprotect(stream).unwrap() == "Obtuse").nth(0).expect("Attach entry is missing");
    let (attach_name, attach_value) = attach_entry.get_binary(1);
    assert_eq!(attach_name, "secret.bin", "Wrong attach name");
    //assert_eq!(String::from_utf8_lossy(attach_value), "secret\n", "Wrong attach value");
    Ok(())
}
