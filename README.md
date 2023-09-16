[KeePass-DB][docsrs]: KeePass database for KBD and KBDX file formats
========================================

[![KeePass-DB GitHub Actions][gh-image]][gh-checks]
[![KeePass-DB on crates.io][cratesio-image]][cratesio]
[![KeePass-DB on docs.rs][docsrs-image]][docsrs]
[![Chat][zulip-image]][zulip]
[![codecov.io][codecov-img]][codecov-link]
[![dependency status](https://deps.rs/repo/github/penguin359/keepass-db/status.svg)](https://deps.rs/repo/github/penguin359/keepass-db)
[![License file](https://img.shields.io/github/license/penguin359/keepass-db)](https://github.com/penguin359/keepass-db/blob/main/LICENSE)

[gh-image]: https://github.com/penguin359/keepass-db/actions/workflows/tests.yml/badge.svg
[gh-checks]: https://github.com/penguin359/keepass-db/actions/workflows/tests.yml
[cratesio-image]: https://img.shields.io/crates/v/keepass-db.svg
[cratesio]: https://crates.io/crates/keepass-db
[docsrs-image]: https://docs.rs/keepass-db/badge.svg
[docsrs]: https://docs.rs/keepass-db
[zulip-image]: https://img.shields.io/badge/zulip-join_chat-brightgreen.svg
[zulip]: https://penguin359.zulipchat.com/#narrow/stream/404877-keepass-db
[codecov-img]: https://img.shields.io/codecov/c/github/penguin359/keepass-db?logo=codecov
[codecov-link]: https://codecov.io/gh/penguin359/keepass-db

Read and write KeePass password databases. This should be able to read all known
versions supported by the official KeePass software package and as well as a few
variants only supported via extensions.

Write support is currently experimental.

## Example code

To find and print a password based on website URL:

```rust
use keepass_db::{KeePassDoc, protected_stream::CipherValue, Key};
fn main() -> Result<(), Error> {
    let mut key = Key::new();
    key.set_user_password("secret");
    let mut doc = KeePassDoc::load_file("passwords.kdbx", &key)?;
    let database = doc.file;
    let stream = &mut doc.cipher;
    let basic_entry = database.root_group().all_entries().filter(|e| e.url().unprotect(stream).unwrap() == "https://www.example.com/").last().unwrap();
    println!("Password: {}", basic_entry.password().unprotect(stream).unwrap());
    Ok(())
}
```

## Crate features

Default features:

* `argonautica`: Default, well-tested Argon2 implementation

Optional features:

* `rust-argon2`: Original Argon2 support. Not recommended. Must not be enabled with other Argon2 features.
* `argon2-kdf`: Original C implementation of Argon2. Must not be enabled with other Argon2 features.
* `write`: **Experimental:** Enable write support for KeePass database.

## Rust version requirements

The Minimum Supported Rust Version (MSRV) is currently **Rust 1.66.0**.

The MSRV is explicitly tested in CI. It may be bumped in minor releases, but this is not done
lightly.

## License

This project is licensed under

* [MIT License](https://opensource.org/licenses/MIT)
