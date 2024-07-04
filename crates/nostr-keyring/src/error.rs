// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

use std::io;

use nostr::prelude::*;
use thiserror::Error;

/// Nostr Keyring error
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error
    #[error(transparent)]
    IO(#[from] io::Error),
    /// Key error
    #[error(transparent)]
    Key(#[from] key::Error),
    /// NIP-49 error
    #[error(transparent)]
    NIP49(#[from] nip49::Error),
    /// Keyring data too short
    #[error("Keyring data too short")]
    InvalidKeyringLen,
    /// Unknown keyring version
    #[error("Unknown keyring version: {0}")]
    UnknownVersion(u8),
    /// TLV error
    #[error("TLV (type-length-value) error: {0:?}")]
    TLV(TlvError),
    /// Field missing
    #[error("Field missing: {0}")]
    FieldMissing(String),
    /// Can't get home directory
    #[cfg(not(all(target_os = "android", target_os = "ios")))]
    #[error("Can't get home directory")]
    CantGetHomeDir,
    /// Watch only account
    #[error("Watch only account")]
    WatchOnlyAccount,
}

#[derive(Debug)]
pub enum TlvError {
    Type,
    Len,
    Value,
}
