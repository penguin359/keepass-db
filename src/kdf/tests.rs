use hex::FromHex;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::utils::{make_u32, make_u64};
use super::*;

#[test]
#[cfg(feature = "rust-argon2")]
fn test_argon2() {
    use ::argon2::{Config, Variant, Version};

    let password = b"password";
    let salt = b"othersalt";
    let config = Config {
        variant: Variant::Argon2d,
        version: Version::Version13,
        mem_cost: 65536,
        time_cost: 10,
        lanes: 4,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };
    let hash = ::argon2::hash_encoded(password, salt, &config).unwrap();
    let matches = ::argon2::verify_encoded(&hash, password).unwrap();
    assert!(matches);
}

//const ARGON2_HASH : &str = "4eb4d1f66ae3c88d85445fb49ae7c4a8fd51eeaa132c53cb8b37610f02569371";

#[test]
#[cfg(any(feature = "rust-argon2", feature = "argonautica", feature = "argon2-kdf", feature = "argon2"))]
fn test_argon2_kdf() {
    //let data = Vec::from_hex(crate::tests::PASSWORD_SIMPLE).unwrap();
    //let mut key = Key::new();
    //key.set_user_password(data);
    //let composite_key = Vec::from_hex(crate::tests::COMPOSITE_KEY_PASSWORD).unwrap();
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
#[cfg(any(feature = "rust-argon2", feature = "argonautica", feature = "argon2-kdf", feature = "argon2"))]
fn test_argon2_kdf_alternate() {
    let password = b"asdf";
    let salt = b"7kAWcXSFs31RtR0g";
    let hash = "ebe1a1494699ef897bed68f8d934697644e3c5f9b0e9162e2e888d2901fa1ee7";
    let hash_raw = Vec::from_hex(hash).unwrap();
    let mut custom_data = HashMap::new();
    custom_data.insert("S".to_string(), salt.to_vec());
    custom_data.insert("V".to_string(), make_u32(0x13));
    custom_data.insert("M".to_string(), make_u64(32*1024));
    custom_data.insert("I".to_string(), make_u64(20));
    custom_data.insert("P".to_string(), make_u32(3));
    let transform_key = transform_argon2(&password[..], &custom_data);
    assert!(transform_key.is_ok());
    let transform_key_raw = transform_key.unwrap();
    assert_eq!(transform_key_raw, hash_raw);
}

#[test]
#[ignore = "Test incomplete"]
fn test_argon2_kdf_defaults() {
    assert!(false);
}

#[test]
#[ignore = "Test incomplete"]
fn test_argon2_kdf_secret_and_associative() {
    assert!(false);
}
