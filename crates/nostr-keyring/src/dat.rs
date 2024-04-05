// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

//! Keyring.dat file (TLV format)

use std::collections::BTreeSet;

use nostr::prelude::*;

use super::constants::{ACCOUNT, NAME, PUBLIC_KEY, SECRET_KEY_ENCRYPTED, SECRET_KEY_UNENCRYPTED};
use super::{Error, Version};
use crate::account::{Account, AccountSecretKey};
use crate::error::TlvError;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NostrKeyringIntermediate {
    pub version: Version,
    pub accounts: BTreeSet<Account>,
}

impl NostrKeyringIntermediate {
    /// Parse keyring bytes
    pub fn parse(mut bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 1 {
            // Get version
            // SAFETY: bytes len checked above
            let version: Version = Version::try_from(bytes[0])?;

            // Remove version byte
            bytes = &bytes[1..];

            let mut accounts: BTreeSet<Account> = BTreeSet::new();

            match version {
                Version::V1 => {
                    parse_v1(bytes, &mut accounts)?;
                }
            }

            Ok(Self { version, accounts })
        } else {
            Err(Error::InvalidKeyringLen)
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(1);

        // Push version
        bytes.push(self.version as u8);

        // Iter and encode accounts
        for account in self.accounts.iter() {
            let encoded: Vec<u8> = encode_account_v1(account);
            bytes.push(ACCOUNT);
            bytes.push(encoded.len() as u8);
            bytes.extend(encoded);
        }

        bytes
    }
}

fn parse_v1(mut bytes: &[u8], accounts: &mut BTreeSet<Account>) -> Result<(), Error> {
    while !bytes.is_empty() {
        // Get type, len and value
        let t: &u8 = bytes.first().ok_or(Error::TLV(TlvError::Type))?;
        let l: usize = bytes.get(1).copied().ok_or(Error::TLV(TlvError::Len))? as usize;
        let v: &[u8] = bytes.get(2..l + 2).ok_or(Error::TLV(TlvError::Value))?;

        if t == &ACCOUNT {
            let account: Account = parse_v1_account(v)?;
            accounts.insert(account);
        } else {
            // TODO: return error?
            eprintln!("unexpected type: {t}");
        }

        bytes = &bytes[l + 2..];
    }

    Ok(())
}

/// Parse account
fn parse_v1_account(mut value: &[u8]) -> Result<Account, Error> {
    let mut name: Option<String> = None;
    let mut public_key: Option<PublicKey> = None;
    let mut secret_key: Option<AccountSecretKey> = None;

    while !value.is_empty() {
        // Get type, len and value
        let t: &u8 = value.first().ok_or(Error::TLV(TlvError::Type))?;
        let l: usize = value.get(1).copied().ok_or(Error::TLV(TlvError::Len))? as usize;
        let v: &[u8] = value.get(2..l + 2).ok_or(Error::TLV(TlvError::Value))?;

        match t {
            &NAME => {
                if name.is_none() {
                    name = Some(String::from_utf8_lossy(v).to_string());
                }
            }
            &PUBLIC_KEY => {
                if public_key.is_none() {
                    public_key = Some(PublicKey::from_slice(v)?);
                }
            }
            &SECRET_KEY_ENCRYPTED => {
                if secret_key.is_none() {
                    let encrypted_key: EncryptedSecretKey = EncryptedSecretKey::from_slice(v)?;
                    secret_key = Some(AccountSecretKey::Encrypted(encrypted_key));
                }
            }
            &SECRET_KEY_UNENCRYPTED => {
                if secret_key.is_none() {
                    let sk: SecretKey = SecretKey::from_slice(v)?;
                    secret_key = Some(AccountSecretKey::Unencrypted(sk));
                }
            }
            _ => {}
        }

        value = &value[l + 2..];
    }

    Ok(Account {
        name: name.ok_or_else(|| Error::FieldMissing(String::from("name")))?,
        public_key: public_key.ok_or_else(|| Error::FieldMissing(String::from("public key")))?,
        secret_key: secret_key.ok_or_else(|| Error::FieldMissing(String::from("secret key")))?,
    })
}

fn encode_account_v1(account: &Account) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();

    // Name
    bytes.push(NAME);
    bytes.push(account.name.as_bytes().len() as u8);
    bytes.extend(account.name.as_bytes());

    // Public Key
    bytes.push(PUBLIC_KEY);
    bytes.push(account.public_key.to_bytes().len() as u8);
    bytes.extend(account.public_key.to_bytes());

    // Secret Key
    match &account.secret_key {
        AccountSecretKey::Encrypted(k) => {
            let b: Vec<u8> = k.as_vec();
            bytes.push(SECRET_KEY_ENCRYPTED);
            bytes.push(b.len() as u8);
            bytes.extend(b);
        }
        AccountSecretKey::Unencrypted(k) => {
            bytes.push(SECRET_KEY_UNENCRYPTED);
            bytes.push(k.as_secret_bytes().len() as u8);
            bytes.extend(k.as_secret_bytes());
        }
    };

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_keyring() {
        let mut accounts = BTreeSet::new();
        accounts.insert(Account {
            name: String::from("Test"),
            public_key: PublicKey::parse(
                "npub12y7dhz8erxua6gyjvra8c0fj9wcm5g2vkzyflfjwa452k2eu9quslf2zze",
            )
            .unwrap(),
            secret_key: AccountSecretKey::Unencrypted(
                SecretKey::parse("nsec12kcgs78l06p30jz7z7h3n2x2cy99nw2z6zspjdp7qc206887mwvs95lnkx")
                    .unwrap(),
            ),
        });
        accounts.insert(Account {
            name: String::from("Test 2"),
            public_key: PublicKey::parse("672a31bfc59d3f04548ec9b7daeeba2f61814e8ccc40448045007f5479f693a3").unwrap(),
            secret_key: AccountSecretKey::Encrypted(EncryptedSecretKey::from_bech32("ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p").unwrap()),
        });

        let keyring = NostrKeyringIntermediate {
            version: Version::V1,
            accounts,
        };

        let encoded = keyring.encode();

        let decoded = NostrKeyringIntermediate::parse(&encoded).unwrap();

        assert_eq!(keyring, decoded);
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    use super::*;

    const KEYRING: [u8; 214] = [
        1, 0, 74, 1, 4, 84, 101, 115, 116, 2, 32, 81, 60, 219, 136, 249, 25, 185, 221, 32, 146, 96,
        250, 124, 61, 50, 43, 177, 186, 33, 76, 176, 136, 159, 166, 78, 237, 104, 171, 43, 60, 40,
        57, 4, 32, 85, 176, 136, 120, 255, 126, 131, 23, 200, 94, 23, 175, 25, 168, 202, 193, 10,
        89, 185, 66, 208, 160, 25, 52, 62, 6, 20, 253, 28, 254, 219, 153, 0, 135, 1, 6, 84, 101,
        115, 116, 32, 50, 2, 32, 103, 42, 49, 191, 197, 157, 63, 4, 84, 142, 201, 183, 218, 238,
        186, 47, 97, 129, 78, 140, 204, 64, 68, 128, 69, 0, 127, 84, 121, 246, 147, 163, 3, 91, 2,
        16, 82, 215, 195, 248, 88, 14, 123, 65, 149, 51, 129, 229, 188, 73, 100, 107, 195, 63, 2,
        167, 220, 170, 200, 189, 216, 218, 35, 205, 68, 151, 131, 36, 11, 110, 188, 18, 237, 238,
        167, 191, 0, 184, 232, 128, 52, 64, 222, 123, 62, 149, 25, 195, 231, 52, 203, 42, 201, 162,
        17, 234, 45, 197, 35, 18, 229, 17, 122, 17, 163, 2, 45, 129, 58, 180, 56, 113, 156, 160,
        181, 4, 161, 25, 59, 229, 16, 195, 174, 231, 118,
    ];

    #[bench]
    pub fn parse_keyring(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(NostrKeyringIntermediate::parse(&KEYRING)).unwrap();
        });
    }

    #[bench]
    pub fn encode_keyring(bh: &mut Bencher) {
        let mut accounts = BTreeSet::new();
        accounts.insert(Account {
            name: String::from("Test"),
            public_key: PublicKey::parse(
                "npub12y7dhz8erxua6gyjvra8c0fj9wcm5g2vkzyflfjwa452k2eu9quslf2zze",
            )
            .unwrap(),
            secret_key: AccountSecretKey::Unencrypted(
                SecretKey::parse("nsec12kcgs78l06p30jz7z7h3n2x2cy99nw2z6zspjdp7qc206887mwvs95lnkx")
                    .unwrap(),
            ),
        });
        accounts.insert(Account {
            name: String::from("Test 2"),
            public_key: PublicKey::parse("672a31bfc59d3f04548ec9b7daeeba2f61814e8ccc40448045007f5479f693a3").unwrap(),
            secret_key: AccountSecretKey::Encrypted(EncryptedSecretKey::from_bech32("ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p").unwrap()),
        });
        let keyring = NostrKeyringIntermediate {
            version: Version::V1,
            accounts,
        };

        bh.iter(|| {
            black_box(keyring.encode());
        });
    }
}
