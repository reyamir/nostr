// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use nostr::prelude::*;

use crate::constants::{NAME, PUBLIC_KEY, SECRET_KEY_ENCRYPTED, SECRET_KEY_UNENCRYPTED};
use crate::error::TlvError;
use crate::{Error, Version};

/// Secret Key
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountSecretKey {
    /// Encrypted
    Encrypted(EncryptedSecretKey),
    /// Unencrypted
    Unencrypted(SecretKey),
}

impl AccountSecretKey {
    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::Encrypted(..) => EncryptedSecretKey::LEN,
            Self::Unencrypted(..) => SecretKey::LEN,
        }
    }
}

/// Account
#[derive(Debug, Clone)]
pub struct Account {
    pub(crate) version: Version,
    pub(crate) name: String,
    pub(crate) public_key: PublicKey,
    pub(crate) secret_key: Option<AccountSecretKey>,
}

impl PartialEq for Account {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key && self.secret_key == other.secret_key
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

impl Hash for Account {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.public_key.hash(state);
    }
}

impl Account {
    #[inline]
    pub fn new<S>(name: S, public_key: PublicKey) -> Self
    where
        S: Into<String>,
    {
        Self {
            version: Version::default(),
            name: name.into(),
            public_key,
            secret_key: None,
        }
    }

    #[inline]
    pub fn empty(public_key: PublicKey) -> Self {
        Self::new("", public_key)
    }

    /// Parse account
    pub fn parse(mut bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 1 {
            // Get version
            // SAFETY: bytes len checked above
            let version: Version = Version::try_from(bytes[0])?;

            // Remove version byte
            bytes = &bytes[1..];

            match version {
                Version::V1 => {
                    let mut name: Option<String> = None;
                    let mut public_key: Option<PublicKey> = None;
                    let mut secret_key: Option<AccountSecretKey> = None;

                    while !bytes.is_empty() {
                        // Get type, len and value
                        let t: &u8 = bytes.first().ok_or(Error::TLV(TlvError::Type))?;
                        let l: usize =
                            bytes.get(1).copied().ok_or(Error::TLV(TlvError::Len))? as usize;
                        let v: &[u8] = bytes.get(2..l + 2).ok_or(Error::TLV(TlvError::Value))?;

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
                                    let encrypted_key: EncryptedSecretKey =
                                        EncryptedSecretKey::from_slice(v)?;
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

                        bytes = &bytes[l + 2..];
                    }

                    Ok(Self {
                        version,
                        name: name.ok_or_else(|| Error::FieldMissing(String::from("name")))?,
                        public_key: public_key
                            .ok_or_else(|| Error::FieldMissing(String::from("public key")))?,
                        secret_key,
                    })
                }
            }
        } else {
            Err(Error::InvalidKeyringLen)
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let name: &[u8] = self.name.as_bytes();
        let public_key: [u8; 32] = self.public_key.to_bytes();
        let secret_key_len: usize = match &self.secret_key {
            Some(sk) => 2 + sk.len(),
            None => 0,
        };

        let mut bytes: Vec<u8> = Vec::with_capacity(1 + 2 + name.len() + 2 + 32 + secret_key_len);

        // Push version
        bytes.push(self.version as u8);

        // Name
        bytes.push(NAME);
        bytes.push(name.len() as u8);
        bytes.extend(name);

        // Public Key
        bytes.push(PUBLIC_KEY);
        bytes.push(public_key.len() as u8);
        bytes.extend(public_key);

        // Secret Key
        match &self.secret_key {
            Some(AccountSecretKey::Encrypted(k)) => {
                let b: Vec<u8> = k.as_vec();
                bytes.push(SECRET_KEY_ENCRYPTED);
                bytes.push(b.len() as u8);
                bytes.extend(b);
            }
            Some(AccountSecretKey::Unencrypted(k)) => {
                bytes.push(SECRET_KEY_UNENCRYPTED);
                bytes.push(k.as_secret_bytes().len() as u8);
                bytes.extend(k.as_secret_bytes());
            }
            None => {}
        };

        bytes
    }

    /// Get account name
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get public key
    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Check if secret key is encrypted
    #[inline]
    pub fn is_encrypted(&self) -> bool {
        matches!(self.secret_key, Some(AccountSecretKey::Encrypted(..)))
    }

    /// Get secret key
    #[inline]
    pub fn secret_key(&self) -> Option<&AccountSecretKey> {
        self.secret_key.as_ref()
    }

    /// Compose [Keys] from secret key
    ///
    /// You can leave the password blank if the secret key is unencrypted.
    /// Use `is_encrypted` method to check if it's encrypted or not.
    #[inline]
    pub fn keys<S>(&self, password: S) -> Result<Keys, Error>
    where
        S: AsRef<str>,
    {
        let secret_key: SecretKey = match self.secret_key.clone() {
            Some(AccountSecretKey::Encrypted(encrypted_key)) => {
                encrypted_key.to_secret_key(password)?
            }
            Some(AccountSecretKey::Unencrypted(secret_key)) => secret_key,
            None => return Err(Error::WatchOnlyAccount),
        };
        Ok(Keys::new(secret_key))
    }

    // pub(crate) fn change_name<S>(&mut self, name: S)
    // where
    //     S: Into<String>
    // {
    //     self.name = name.into();
    // }
    //
    // /// Change password (if unencrypted, encrypt it)
    // pub fn change_password<S>(&mut self, current_password: S, new_password: S) -> Result<(), Error>
    // where
    //     S: AsRef<str>
    // {
    //     todo!()
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_keyring() {
        let account = Account {
            version: Version::V1,
            name: String::from("Test"),
            public_key: PublicKey::parse(
                "npub12y7dhz8erxua6gyjvra8c0fj9wcm5g2vkzyflfjwa452k2eu9quslf2zze",
            )
            .unwrap(),
            secret_key: Some(AccountSecretKey::Unencrypted(
                SecretKey::parse("nsec12kcgs78l06p30jz7z7h3n2x2cy99nw2z6zspjdp7qc206887mwvs95lnkx")
                    .unwrap(),
            )),
        };

        let encoded: Vec<u8> = account.encode();

        let decoded: Account = Account::parse(&encoded).unwrap();

        assert_eq!(account, decoded);
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    use super::*;

    const KEYRING: [u8; 75] = [
        1, 1, 4, 84, 101, 115, 116, 2, 32, 81, 60, 219, 136, 249, 25, 185, 221, 32, 146, 96, 250,
        124, 61, 50, 43, 177, 186, 33, 76, 176, 136, 159, 166, 78, 237, 104, 171, 43, 60, 40, 57,
        4, 32, 85, 176, 136, 120, 255, 126, 131, 23, 200, 94, 23, 175, 25, 168, 202, 193, 10, 89,
        185, 66, 208, 160, 25, 52, 62, 6, 20, 253, 28, 254, 219, 153,
    ];

    #[bench]
    pub fn parse_keyring(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(Account::parse(&KEYRING)).unwrap();
        });
    }

    #[bench]
    pub fn encode_keyring(bh: &mut Bencher) {
        let account = Account {
            version: Version::V1,
            name: String::from("Test"),
            public_key: PublicKey::parse(
                "npub12y7dhz8erxua6gyjvra8c0fj9wcm5g2vkzyflfjwa452k2eu9quslf2zze",
            )
            .unwrap(),
            secret_key: AccountSecretKey::Unencrypted(
                SecretKey::parse("nsec12kcgs78l06p30jz7z7h3n2x2cy99nw2z6zspjdp7qc206887mwvs95lnkx")
                    .unwrap(),
            ),
        };

        bh.iter(|| {
            black_box(account.encode());
        });
    }
}
