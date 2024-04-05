// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

use std::cmp::Ordering;

use nostr::prelude::*;

/// Secret Key
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountSecretKey {
    /// Encrypted
    Encrypted(EncryptedSecretKey),
    /// Unencrypted
    Unencrypted(SecretKey),
}

/// Account
#[derive(Debug, Clone)]
pub struct Account {
    pub(crate) name: String,
    pub(crate) public_key: PublicKey,
    pub(crate) secret_key: AccountSecretKey, // TODO: allow only encrypted secret key?
}

impl PartialEq for Account {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl Eq for Account {}

impl PartialOrd for Account {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Account {
    fn cmp(&self, other: &Self) -> Ordering {
        // Sort ASC by name.
        // If name are equals, sort by public key.
        if self.name != other.name {
            self.name.cmp(&other.name)
        } else {
            self.public_key.cmp(&other.public_key)
        }
    }
}

impl Account {
    #[inline]
    pub fn new<S>(name: S, public_key: PublicKey, secret_key: AccountSecretKey) -> Self
    where
        S: Into<String>,
    {
        Self {
            name: name.into(),
            public_key,
            secret_key,
        }
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    #[inline]
    pub fn secret_key(&self) -> &AccountSecretKey {
        &self.secret_key
    }
}
