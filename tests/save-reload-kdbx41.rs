use std::convert::Into;
use std::{io::Result, path::PathBuf};
use std::io::{prelude::*, SeekFrom};

use keepass_db::{KeePassDoc, protected_stream::CipherValue, Key};

use tempfile::tempfile;

#[cfg(feature = "write")]
#[test]
fn main() -> Result<()> {
    let key = Key::with_password("asdf");
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("dummy-kdbx41.kdbx");
    let mut expected = KeePassDoc::load_file(file, &key)?;

    let mut saved_file = tempfile().expect("Failed to create temp file");

    expected.save(&mut saved_file, 4)?;
    saved_file.seek(SeekFrom::Start(0))?;
    let actual = KeePassDoc::load(&mut saved_file, &key)?;
    let database = expected.file;
    let stream = &mut expected.cipher;
    println!("Groups:");
    for g in database.root_group().all_groups() {
        println!("  {title}", title=g.name());
    }
    Ok(())
}
