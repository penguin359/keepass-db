use log::{info, debug};

#[cfg(feature = "rust-argon2")]
use ::argon2::{Config, Variant, Version};
#[cfg(feature = "argonautica")]
use argonautica::{
    config::{Variant, Version},
    Hasher,
};
#[cfg(feature = "argon2-kdf")]
use argon2_kdf::{Hasher, Algorithm};
#[cfg(feature = "argon2")]
use ::argon2::{Argon2, Algorithm, Version, ParamsBuilder};

use crate::MapValue;
use super::*;

/* TODO Use these defaults */
const _DEFAULT_ITERATIONS: u64 = 2;
const _DEFAULT_MEMORY: u64 = 1024 * 1024;
const _DEFAULT_PARALLELISM: u32 = 2;

#[cfg(feature = "rust-argon2")]
fn transform_argon2_lib(
    composite_key: &[u8],
    salt: &[u8],
    version: u32,
    mem_cost: u32,
    time_cost: u32,
    lanes: u32,
) -> io::Result<Vec<u8>> {
    debug!("Rust Argon2");
    let version = match version {
        0x13 => Version::Version13,
        0x10 => Version::Version10,
        _ => {
            panic!("Misconfigured!");
        }
    };
    let config = Config {
        variant: Variant::Argon2d,
        version,
        mem_cost,
        time_cost,
        lanes,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };
    let hash = ::argon2::hash_raw(composite_key, salt, &config).unwrap();
    println!(
        "P: {:0x?}, S: {:0x?}, H: {:0x?}, C: {:#?}",
        composite_key, salt, hash, config
    );
    Ok(hash)
}

#[cfg(feature = "argonautica")]
fn transform_argon2_lib(
    composite_key: &[u8],
    salt: &[u8],
    version: u32,
    mem_cost: u32,
    time_cost: u32,
    lanes: u32,
) -> io::Result<Vec<u8>> {
    debug!("Argonautica");
    let version = match version {
        0x13 => Version::_0x13,
        0x10 => Version::_0x10,
        _ => {
            panic!("Misconfigured!");
        }
    };
    let mut hasher = Hasher::default();
    hasher
        .configure_iterations(time_cost)
        .configure_lanes(lanes)
        .configure_memory_size(mem_cost)
        .configure_variant(Variant::Argon2d)
        .configure_version(version)
        .opt_out_of_secret_key(true);
    //println!("P: {:0x?}, S: {:0x?}, H: {:0x?}, C: {:#?}", composite_key, salt, b"", hasher);//hash, config);
    Ok(hasher
        .with_password(composite_key)
        .with_salt(salt)
        .hash_raw()
        .unwrap()
        .raw_hash_bytes()
        .to_owned())
}

#[cfg(feature = "argon2-kdf")]
fn transform_argon2_lib(
    composite_key: &[u8],
    salt: &[u8],
    version: u32,
    mem_cost: u32,
    time_cost: u32,
    lanes: u32,
) -> io::Result<Vec<u8>> {
    debug!("Argon2-KDF");
    Ok(Hasher::new()
            .algorithm(Algorithm::Argon2d)
            .custom_salt(salt)
            .hash_length(32)
            .iterations(time_cost)
            .memory_cost_kib(mem_cost)
            .threads(lanes)
            .hash(composite_key)
            .unwrap()
            .as_bytes()
            .to_owned())
}

#[cfg(feature = "argon2")]
fn transform_argon2_lib(
    composite_key: &[u8],
    salt: &[u8],
    version: u32,
    mem_cost: u32,
    time_cost: u32,
    lanes: u32,
) -> io::Result<Vec<u8>> {
    debug!("Argon2");
    let version = match version {
        0x13 => Version::V0x13,
        0x10 => Version::V0x10,
        _ => {
            panic!("Misconfigured!");
        }
    };
    let mut hash = [0; 32];
    Argon2::new(Algorithm::Argon2d, version, ParamsBuilder::new()
        .m_cost(mem_cost)
        .t_cost(time_cost)
        .p_cost(lanes)
        .output_len(32)
        .build()
        .unwrap()
    ).hash_password_into(composite_key, &salt, &mut hash).unwrap();
    Ok(hash.to_vec())
}

#[cfg(any(feature = "rust-argon2", feature = "argonautica", feature = "argon2-kdf", feature = "argon2"))]
pub fn transform_argon2(
    composite_key: &[u8],
    custom_data: &HashMap<String, MapValue>,
) -> io::Result<Vec<u8>> {
    info!("Found Argon2 KDF");
    let salt = match custom_data.get(KDF_PARAM_SALT) {
        Some(MapValue::ByteArray(x)) => x,
        _ => {
            return Err(io::Error::new(io::ErrorKind::Other, "Argon2 salt missing"));
        }
    };
    let version = match custom_data.get(KDF_PARAM_VERSION) {
        Some(MapValue::UInt32(x)) => match *x {
            x if x > 0x13 => {
                println!("Version: {}", x);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Argon2 version too new",
                ));
            }
            x if x == 0x13 => 0x13,
            x if x >= 0x10 => 0x10,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Argon2 version too old",
                ));
            }
        },
        Some(_) => {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid version"));
        },
        None => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Argon2 version missing",
            ));
        }
    };
    let mem_cost = match custom_data.get(KDF_PARAM_MEMORY) {
        Some(MapValue::UInt64(x)) => x / 1024,
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Invalid memory parameter",
            ));
        },
        None => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Argon2 memory parameter missing",
            ));
        }
    };
    let time_cost = match custom_data.get(KDF_PARAM_ITERATIONS) {
        Some(MapValue::UInt64(x)) => *x,
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Invalid time parameter",
            ));
        },
        None => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Argon2 time parameter missing",
            ));
        }
    };
    let lanes = match custom_data.get(KDF_PARAM_PARALLELISM) {
        Some(MapValue::UInt32(x)) => *x,
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Invalid parallelism parameter",
            ));
        },
        None => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Argon2 parallelism parameter missing",
            ));
        }
    };
    let hash = transform_argon2_lib(
        composite_key,
        salt,
        version,
        mem_cost as u32,
        time_cost as u32,
        lanes,
    )
    .unwrap();
    Ok(hash)
}

#[cfg(not(any(feature = "rust-argon2", feature = "argonautica", feature = "argon2-kdf", feature = "argon2")))]
pub fn transform_argon2(
    _composite_key: &[u8],
    custom_data: &HashMap<String, MapValue>,
) -> io::Result<Vec<u8>> {
    Err(io::Error::new(io::ErrorKind::Other, "Argon2 unimplemented"))
}
