use std::{process::Command, path::PathBuf};

#[test]
fn main() {
    assert!(Command::new(env!("CARGO_BIN_EXE_keepass-db"))
        .env("KDBX_PASSWORD","asdf")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("keepass-1.41.kdb"))
        .status()
        .expect("failed to execute process").success());
}
