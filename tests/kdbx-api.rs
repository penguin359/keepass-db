use std::convert::Into;
use std::{io::Result, path::PathBuf};

use kdbx::{lib_main, protected_stream::CipherValue, Key};

#[test]
fn main() -> Result<()> {
    let mut key = Key::new();
    key.set_user_password("asdf");
    let mut stream = kdbx::protected_stream::new_stream(0, &[]).unwrap();
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("dummy-kdbx41.kdbx");
    let database = lib_main(file.to_str().unwrap(), &key)?;
    assert_eq!(database.groups().len(), 1);
    println!("Groups:");
    for g in database.groups()[0].all_groups() {
        println!("  {title}", title=g.name());
    }
    assert_eq!(database.groups()[0].all_groups().count(), 9);
    println!("Entries:");
    for g in database.groups()[0].all_entries() {
        println!("  {title}", title=g.title().unprotect(&mut stream).unwrap());
    }
    assert_eq!(database.groups()[0].all_entries().count(), 10);
    let full_entry = database.groups()[0].all_entries().nth(4).expect("Fifth entry is missing");
    assert_eq!(full_entry.title().unprotect(&mut stream).unwrap(), "Full");
    assert_eq!(full_entry.username().unprotect(&mut stream).unwrap(), "johndoe");
    //assert_eq!(full_entry.password().unprotect(&mut stream).unwrap(), "FG54PY9Z8PDTV-7C1");
    assert_eq!(full_entry.url().unprotect(&mut stream).unwrap(), "http://www.example.org/");
    assert_eq!(full_entry.notes().unprotect(&mut stream).unwrap(), "A complete entry as much as possible.");
    let basic_entry = database.groups()[0].all_entries().filter(|e| e.title().unprotect(&mut stream).unwrap() == "Basic").nth(0).expect("Fifth entry is missing");
    assert_eq!(basic_entry.username().unprotect(&mut stream).unwrap(), "user");
    Ok(())
}
