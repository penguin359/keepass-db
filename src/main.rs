use std::io;

use clap::{App, Arg};

use kdbx::lib_main;

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

    lib_main(filename, options.value_of("key"))?;
    println!("Done!");

    Ok(())
}
