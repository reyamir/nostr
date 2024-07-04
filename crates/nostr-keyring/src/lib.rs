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

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nostr::prelude::*;
use thiserror::Error;
use tokio::sync::RwLock;

mod account;
mod constants;
mod error;
pub mod prelude;
mod version;

pub use self::account::{Account, AccountSecretKey};
use self::constants::EXTENSION;
pub use self::error::Error;
pub use self::version::Version;

/// Nostr Keyring
#[derive(Debug, Clone)]
pub struct NostrKeyring {
    path: PathBuf,
    account: Account,
}

impl NostrKeyring {
    /// Open keyring
    ///
    /// Will open the keyring at `$HOME/.nostr/keyring/<public_key>.dat`.
    /// If not exists, will be created an new one.
    ///
    /// |Platform | Path                                              |
    /// | ------- | ------------------------------------------------- |
    /// | Linux   | `/home/<user>/.nostr/keyring/<public_key>.dat`    |
    /// | macOS   | `/Users/<user>/.nostr/keyring/<public_key>.dat`   |
    /// | Windows | `C:\Users\<user>\.nostr\keyring/<public_key>.dat` |
    #[cfg(not(all(target_os = "android", target_os = "ios")))]
    pub fn open(public_key: PublicKey) -> Result<Self, Error> {
        let home_dir: PathBuf = dirs::home_dir().ok_or(Error::CantGetHomeDir)?;
        let nostr_dir: PathBuf = home_dir.join(".nostr/keyring");
        Self::open_in(nostr_dir, public_key)
    }

    /// Open Nostr Keyring from custom path
    ///
    /// If not exists, will be created an new one.
    pub fn open_in<P>(base_path: P, public_key: PublicKey) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let base_path: &Path = base_path.as_ref();

        // Create dirs if not exists
        fs::create_dir_all(base_path)?;

        // Compose keychain path
        let mut path: PathBuf = base_path.join(public_key.to_hex());
        path.set_extension(EXTENSION);

        // Check if `keyring.dat` file exists
        if path.exists() && path.is_file() {
            // Open file and read it
            let mut file: File = File::open(&path)?;
            let mut buffer: Vec<u8> = Vec::new();
            file.read_to_end(&mut buffer)?;

            Ok(Self {
                path,
                account: Account::parse(&buffer)?,
            })
        } else {
            // Create empty keyring
            Ok(Self {
                path,
                account: Account::empty(public_key),
            })
        }
    }

    /// Get keyring version
    #[inline]
    pub fn version(&self) -> Version {
        self.account.version
    }

    /// Get public key
    #[inline]
    pub fn public_key(&self) -> PublicKey {
        self.account.public_key
    }

    /// Add account to the keyring
    ///
    /// Automatically save the file.
    #[inline]
    pub fn add_account(&mut self, account: Account) -> Result<(), Error> {
        // TODO: remove '&mut self'?
        //self.inner.accounts.insert(account);
        self.save()
    }

    /// Remove account from keyring
    ///
    /// Automatically save the file.
    #[inline]
    pub fn remove_account(&mut self, account: &Account) -> Result<(), Error> {
        // TODO: remove '&mut self'?
        //self.inner.accounts.remove(account);
        self.save()
    }

    // /// Add account to the keyring
    // ///
    // /// Automatically save the file.
    // #[inline]
    // pub fn change_account_name(&mut self, public_key: &PublicKey) -> Result<(), Error> {
    //     //self.inner.accounts.
    //
    //     Ok(())
    // }

    // TODO: bulk_add and bulk_remove

    // TODO: method to change password of account by public key

    /// Write keyring to file
    pub fn save(&self) -> Result<(), Error> {
        let bytes: Vec<u8> = self.account.encode();
        let mut file: File = File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.path.as_path())?;
        file.write_all(&bytes)?;
        Ok(())
    }
}
