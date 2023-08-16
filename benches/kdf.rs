#![feature(test)]

extern crate test;

use std::collections::HashMap;

use test::Bencher;

use kdbx::{AesKdf, Kdf, Key, MapValue, KDF_AES_KDBX3, KDF_PARAM_UUID};

#[bench]
fn bench_me(b: &mut Bencher) {
    b.iter(|| {
        let mut key = Key::new();
        key.set_user_password("asdf");
        let composite_key = key.composite_key();
        let kdf = AesKdf::default();
        let mut custom_data = HashMap::new();
        custom_data.insert(
            KDF_PARAM_UUID.to_string(),
            MapValue::ByteArray(KDF_AES_KDBX3.into_bytes().to_vec()),
        );
        kdf.save(&mut custom_data);
        let transform_key = kdf
            .transform_key(&composite_key)
            .expect("Failed to transform key");
    })
}
