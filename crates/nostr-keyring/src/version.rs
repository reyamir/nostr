// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

use crate::Error;

/// Nostr Keyring version
#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Version {
    /// Version 1
    #[default]
    V1 = 0x01,
}

impl TryFrom<u8> for Version {
    type Error = Error;

    fn try_from(version: u8) -> Result<Self, Self::Error> {
        match version {
            0x01 => Ok(Self::V1),
            v => Err(Error::UnknownVersion(v)),
        }
    }
}
