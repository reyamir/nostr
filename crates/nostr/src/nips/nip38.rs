// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP38: User Statuses
//!
//! <https://github.com/nostr-protocol/nips/blob/master/38.md>

use std::fmt;

/// NIP38 types
#[derive(Debug, PartialEq, Eq)]
pub enum Statuses {
    /// General status: "Working", "Hiking", etc.
    General,
    /// Music what you are currently listening to
    Music,
    /// Custom status: "Playing", "Reading", etc.
    Custom(String),
}

impl fmt::Display for Statuses {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Statuses::General => write!(f, "general"),
            Statuses::Music => write!(f, "music"),
            Statuses::Custom(s) => write!(f, "{}", s),
        }
    }
}
