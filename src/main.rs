use std::env;
use std::io::{self, prelude::*};
use std::fs::File;

use clap::{App, Arg};
use rpassword::read_password;

use kdbx::{Key, lib_main, save_file};

fn main() -> io::Result<()> {
    env_logger::init();

    println!("Hello, world!");

    let options = App::new("KDBX Dump")
        .version("0.1.0")
        .author("Loren M. Lang <lorenl@north-winds.org>")
        .about("Dumping KDBX Password files")
        .arg(
            Arg::with_name("key")
                .short("k")
                .long("key-file")
                .takes_value(true)
                .help("Key file for unlocking database"),
        )
        .arg(
            Arg::with_name("file")
                .help("Password database")
                .required(true)
                .index(1),
        )
        .get_matches();

    let filename = options.value_of("file").expect("missing filename");

    let mut key = Key::new();
    let user_password = match env::var("KDBX_PASSWORD") {
        Ok(password) => password,
        Err(env::VarError::NotPresent) => read_password().unwrap(),
        Err(env::VarError::NotUnicode(_)) => {
            panic!("Invalid password");
        }
    };
    key.set_user_password(user_password);

    if let Some(filename) = options.value_of("key") {
        let mut contents = vec![];
        File::open(filename)?.read_to_end(&mut contents)?;
        key.set_keyfile(contents);
    }

    let doc = lib_main(filename, &key)?.file;
    println!("KeePassFile: {:#?}", &doc);
    save_file(&doc, 4).unwrap();
    println!("Done!");

    Ok(())
}
