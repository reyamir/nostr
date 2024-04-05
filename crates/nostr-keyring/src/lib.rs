// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

//! Nostr Keyring

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]
#![cfg_attr(bench, feature(test))]

#[cfg(bench)]
extern crate test;

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use nostr::prelude::*;
use thiserror::Error;

mod account;
mod constants;
mod dat;
mod error;
pub mod prelude;
mod version;

pub use self::account::{Account, AccountSecretKey};
use self::constants::{DEFAULT_FILE_NAME, EXTENSION};
use self::dat::NostrKeyringIntermediate;
pub use self::error::Error;
pub use self::version::Version;

/// Nostr Keyring
pub struct NostrKeyring {
    path: PathBuf,
    inner: NostrKeyringIntermediate,
}

impl NostrKeyring {
    /// Open keyring
    ///
    /// Will open the keyring at `$HOME/.nostr/keyring.dat`.
    /// If not exists, will be created an empty one.
    ///
    /// |Platform | Path                                 |
    /// | ------- | ------------------------------------ |
    /// | Linux   | `/home/<user>/.nostr/keyring.dat`    |
    /// | macOS   | `/Users/<user>/.nostr/keyring.dat`   |
    /// | Windows | `C:\Users\<user>\.nostr\keyring.dat` |
    #[cfg(not(all(target_os = "android", target_os = "ios")))]
    pub fn open() -> Result<Self, Error> {
        let home_dir: PathBuf = dirs::home_dir().ok_or(Error::CantGetHomeDir)?;
        let nostr_dir: PathBuf = home_dir.join(".nostr");
        Self::open_in(nostr_dir, None)
    }

    /// Open Nostr Keyring from custom path
    ///
    /// If not exists, will be created an empty one.
    pub fn open_in<P>(base_path: P, file_name: Option<&str>) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let base_path: &Path = base_path.as_ref();

        // Create dirs if not exists
        fs::create_dir_all(base_path)?;

        let file_name: &str = file_name.unwrap_or(DEFAULT_FILE_NAME);
        let mut path: PathBuf = base_path.join(file_name);

        // Set file extension
        path.set_extension(EXTENSION);

        // Check if `keyring.dat` file exists
        if path.exists() && path.is_file() {
            // Open file and read it
            let mut file: File = File::open(&path)?;
            let mut buffer: Vec<u8> = Vec::new();
            file.read_to_end(&mut buffer)?;

            Ok(Self {
                path,
                inner: NostrKeyringIntermediate::parse(&buffer)?,
            })
        } else {
            // Create empty keyring
            Ok(Self {
                path,
                inner: NostrKeyringIntermediate::default(),
            })
        }
    }

    /// Get keyring version
    #[inline]
    pub fn version(&self) -> Version {
        self.inner.version
    }

    /// Get list of available accounts
    #[inline]
    pub fn accounts(&self) -> &BTreeSet<Account> {
        &self.inner.accounts
    }

    /// Get account by public key
    #[inline]
    pub fn account_by_public_key(&self, public_key: &PublicKey) -> Option<&Account> {
        self.inner
            .accounts
            .iter()
            .find(|a| &a.public_key == public_key)
    }

    /// Add account to the keyring
    ///
    /// Automatically save the file.
    #[inline]
    pub fn add_account(&mut self, account: Account) -> Result<(), Error> {
        // TODO: remove '&mut self'?
        self.inner.accounts.insert(account);
        self.save()
    }

    /// Remove account from keyring
    ///
    /// Automatically save the file.
    #[inline]
    pub fn remove_account(&mut self, account: &Account) -> Result<(), Error> {
        // TODO: remove '&mut self'?
        self.inner.accounts.remove(account);
        self.save()
    }

    // TODO: bulk_add and bulk_remove

    /// Write keyring to file
    pub fn save(&self) -> Result<(), Error> {
        let bytes: Vec<u8> = self.inner.encode();
        let mut file: File = File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.path.as_path())?;
        file.write_all(&bytes)?;
        Ok(())
    }
}
