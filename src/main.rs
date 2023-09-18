use std::env;
use std::io::{self, prelude::*};
use std::fs::File;

use clap::{Command, Arg};
use rpassword::read_password;

use keepass_db::{Key, KeePassDoc};

fn main() -> io::Result<()> {
    env_logger::init();

    let options = Command::new("KDBX Dump")
        .version("0.1.0")
        .author("Loren M. Lang <lorenl@north-winds.org>")
        .about("Dumping KDBX Password files")
        .help_template("{name} {version}\n\
                        {author-with-newline}\
                        {about-with-newline}\n\
                        {usage-heading} {usage}\n\n\
                        {all-args}")
        .arg(
            Arg::new("key")
                .short('k')
                .long("key-file")
                .help("Key file for unlocking database"),
        )
        .arg(
            Arg::new("file")
                .help("Password database")
                .required(true)
                .index(1),
        )
        .get_matches();

    let filename = options.get_one::<String>("file").expect("missing filename");

    let mut key = Key::new();
    let user_password = match env::var("KDBX_PASSWORD") {
        Ok(password) => password,
        Err(env::VarError::NotPresent) => read_password().unwrap(),
        Err(env::VarError::NotUnicode(_)) => {
            panic!("Invalid password");
        }
    };
    key.set_user_password(user_password);

    if let Some(filename) = options.get_one::<String>("key") {
        let mut contents = vec![];
        File::open(filename)?.read_to_end(&mut contents)?;
        key.set_keyfile(contents);
    }

    let doc = KeePassDoc::load_file(filename, &key)?;
    println!("KeePassFile: {:#?}", &doc.file);

    #[cfg(feature = "write")]
    {
        doc.save_file(4).unwrap();
    }

    println!("Done!");

    Ok(())
}
