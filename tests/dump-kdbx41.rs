use std::{process::Command, path::PathBuf};

#[cfg(feature = "argon2")]
#[test]
fn main() {
    assert!(Command::new(env!("CARGO_BIN_EXE_keepass-db"))
        .env("KDBX_PASSWORD","asdf")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("dummy-kdbx41.kdbx"))
        .status()
        .expect("failed to execute process").success());
}
