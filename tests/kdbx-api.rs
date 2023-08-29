use std::convert::Into;
use std::{io::Result, path::PathBuf};

use kdbx::{lib_main, Key};

#[test]
fn main() -> Result<()> {
    let mut key = Key::new();
    key.set_user_password("asdf");
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("dummy-kdbx41.kdbx");
    let database = lib_main(file.to_str().unwrap(), &key)?;
    assert_eq!(database.groups().len(), 1);
    Ok(())
}
