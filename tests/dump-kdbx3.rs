use std::{process::Command, path::PathBuf};

#[test]
fn main() {
    assert!(Command::new(env!("CARGO_BIN_EXE_kdbx"))
        .env("KDBX_PASSWORD","asdf")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("dummy-kdbx3.kdbx"))
        .status()
        .expect("failed to execute process").success());
}
