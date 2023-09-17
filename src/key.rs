use ring::digest::{Context, SHA256};

/// Composite key protecting the password database
///
/// This key is composed of a password and/or a key file which
/// must be provided when opening a KeePass password database
/// ```
/// use keepass_db::Key;
/// let mut key = Key::new();
/// key.set_user_password("secret");
/// ```
pub struct Key {
    user_password: Option<Vec<u8>>,
    keyfile: Option<Vec<u8>>,
    windows_credentials: Option<Vec<u8>>,
}

impl Key {
    /// Create a new composite key
    /// ```
    /// # use keepass_db::Key;
    /// let mut key = Key::new();
    /// ```
    pub fn new() -> Key {
        Key {
            user_password: None,
            keyfile: None,
            windows_credentials: None,
        }
    }

    /// Set the password for the compsite key
    /// ```
    /// # use keepass_db::Key;
    /// # let mut key = Key::new();
    /// key.set_user_password("secret");
    /// ```
    pub fn set_user_password<T>(&mut self, user_password: T)
    where
        T: AsRef<[u8]>,
    {
        let mut context = Context::new(&SHA256);
        context.update(user_password.as_ref());
        self.user_password = Some(context.finish().as_ref().to_owned());
    }

    /// Load a key file for the composite key
    /// ```
    /// # use keepass_db::Key;
    /// # let mut key = Key::new();
    /// key.set_keyfile("secret");
    /// ```
    pub fn set_keyfile<T>(&mut self, keyfile: T)
    where
        T: AsRef<[u8]>,
    {
        let mut context = Context::new(&SHA256);
        context.update(keyfile.as_ref());
        self.keyfile = Some(context.finish().as_ref().to_owned());
    }

    /* TODO Use this function */
    fn _set_windows_credentials<T>(&mut self, windows_credentials: T)
    where
        T: AsRef<[u8]>,
    {
        let mut context = Context::new(&SHA256);
        context.update(windows_credentials.as_ref());
        self.windows_credentials = Some(context.finish().as_ref().to_owned());
    }

    pub(crate) fn composite_key(&self) -> Vec<u8> {
        let mut context = Context::new(&SHA256);

        if let Some(key) = &self.user_password {
            context.update(&key);
        }

        if let Some(key) = &self.keyfile {
            context.update(&key);
        }

        if let Some(key) = &self.windows_credentials {
            context.update(&key);
        }

        context.finish().as_ref().to_owned()
    }

    pub(crate) fn composite_key_kdb1(&self) -> Vec<u8> {
        if self.user_password == None {
            return self.keyfile.clone().unwrap();
        }

        if self.keyfile == None {
            return self.user_password.clone().unwrap();
        }

        let mut context = Context::new(&SHA256);
        context.update(&self.user_password.clone().unwrap());
        context.update(&self.keyfile.clone().unwrap());
        context.finish().as_ref().to_owned()
    }
}

#[cfg(test)]
mod tests {
    use hex::FromHex;

    use super::*;

    // Simple password is asdf
    const PASSWORD_SIMPLE: &str = "61736466";

    // Composite key generated from simple, password-only lock
    const COMPOSITE_KEY_PASSWORD: &str =
        "fe9a32f5b565da46af951e4aab23c24b8c1565eb0b6603a03118b7d225a21e8c";

    #[test]
    fn test_user_password() {
        let data = Vec::from_hex(PASSWORD_SIMPLE).unwrap();
        let mut key = Key::new();
        key.set_user_password(data);
        assert_eq!(
            key.composite_key(),
            Vec::from_hex(COMPOSITE_KEY_PASSWORD).unwrap()
        );
    }
}
