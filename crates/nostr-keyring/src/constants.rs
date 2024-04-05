// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

pub const DEFAULT_FILE_NAME: &str = "keyring";
pub const EXTENSION: &str = "dat";

pub const ACCOUNT: u8 = 0x00;
pub const NAME: u8 = 0x01;
pub const PUBLIC_KEY: u8 = 0x02;
pub const SECRET_KEY_ENCRYPTED: u8 = 0x03;
pub const SECRET_KEY_UNENCRYPTED: u8 = 0x04;
