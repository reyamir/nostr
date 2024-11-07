// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

//! Nostr Connect client

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use async_utility::time;
use nostr::nips::nip46::{Message, Request, ResponseResult};
use nostr_relay_pool::prelude::*;
use tokio::sync::broadcast::Receiver;
use tokio::sync::OnceCell;

use crate::error::Error;

#[allow(missing_docs)]
#[deprecated(since = "0.36.0", note = "Use `NostrConnect` instead")]
pub type Nip46Signer = NostrConnect;

/// Nostr Connect Client
///
/// <https://github.com/nostr-protocol/nips/blob/master/46.md>
#[derive(Debug, Clone)]
pub struct NostrConnect {
    uri: NostrConnectURI,
    app_keys: Keys,
    remote_signer_public_key: OnceCell<PublicKey>,
    user_public_key: OnceCell<PublicKey>,
    pool: RelayPool,
    timeout: Duration,
    opts: RelayOptions,
    secret: Option<String>,
}

impl NostrConnect {
    /// Construct Nostr Connect client
    pub fn new(
        uri: NostrConnectURI,
        app_keys: Keys,
        timeout: Duration,
        opts: Option<RelayOptions>,
    ) -> Result<Self, Error> {
        // Check app keys
        if let NostrConnectURI::Client { public_key, .. } = &uri {
            if *public_key != app_keys.public_key() {
                return Err(Error::PublicKeyNotMatchAppKeys);
            }
        }

        Ok(Self {
            app_keys,
            // NOT set the remote_signer_public_key, also if bunker URI!
            // If you already set remote_signer_public_key, you'll need another field to know if boostrap was already done.
            remote_signer_public_key: OnceCell::new(),
            user_public_key: OnceCell::new(),
            pool: RelayPool::default(),
            timeout,
            opts: opts.unwrap_or_default(),
            secret: uri.secret(),
            uri,
        })
    }

    async fn bootstrap(&self) -> Result<PublicKey, Error> {
        // Add relays
        for url in self.uri.relays().into_iter() {
            self.pool.add_relay(url, self.opts.clone()).await?;
        }

        // Connect to relays
        self.pool.connect(None).await;

        // Subscribe
        let notifications = self.subscribe().await?;

        // Get remote signer public key
        let remote_signer_public_key: PublicKey = match self.uri.remote_signer_public_key() {
            Some(public_key) => *public_key,
            None => {
                match get_remote_signer_public_key(&self.app_keys, notifications, self.timeout)
                    .await?
                {
                    GetRemoteSignerPublicKey::RemoteOnly(public_key) => public_key,
                    GetRemoteSignerPublicKey::WithUserPublicKey { remote, user } => {
                        // Set user public key
                        self.user_public_key.set(user)?; // This shouldn't fails

                        // Return remote signer public key
                        remote
                    }
                }
            }
        };

        // Send `connect` command if bunker URI
        if self.uri.is_bunker() {
            self.connect(remote_signer_public_key).await?;
        }

        Ok(remote_signer_public_key)
    }

    async fn subscribe(&self) -> Result<Receiver<RelayPoolNotification>, Error> {
        let public_key: PublicKey = self.app_keys.public_key();

        let filter = Filter::new()
            .pubkey(public_key)
            .kind(Kind::NostrConnect)
            .limit(0);

        let notifications = self.pool.notifications();

        // Subscribe
        self.pool
            .subscribe(vec![filter], SubscribeOptions::default())
            .await?;

        Ok(notifications)
    }

    /// Get local app keys
    #[inline]
    pub fn local_keys(&self) -> &Keys {
        &self.app_keys
    }

    /// Get signer relays
    #[inline]
    pub fn relays(&self) -> Vec<Url> {
        self.uri.relays()
    }

    /// Get `bunker` URI
    pub async fn bunker_uri(&self) -> Result<NostrConnectURI, Error> {
        Ok(NostrConnectURI::Bunker {
            remote_signer_public_key: *self.remote_signer_public_key().await?,
            relays: self.relays(),
            secret: self.secret.clone(),
        })
    }

    #[inline]
    async fn remote_signer_public_key(&self) -> Result<&PublicKey, Error> {
        self.remote_signer_public_key
            .get_or_try_init(|| async { self.bootstrap().await })
            .await
    }

    #[inline]
    async fn send_request(&self, req: Request) -> Result<ResponseResult, Error> {
        // Get remote signer public key
        let remote_signer_public_key: PublicKey = *self.remote_signer_public_key().await?;

        // Send request
        self.send_request_with_pk(req, remote_signer_public_key)
            .await
    }

    async fn send_request_with_pk(
        &self,
        req: Request,
        remote_signer_public_key: PublicKey,
    ) -> Result<ResponseResult, Error> {
        let secret_key: &SecretKey = self.app_keys.secret_key();

        // Convert request to event
        let msg = Message::request(req);
        tracing::debug!("Sending '{msg}' NIP46 message");

        let req_id = msg.id().to_string();
        let event: Event =
            EventBuilder::nostr_connect(&self.app_keys, remote_signer_public_key, msg)?
                .sign_with_keys(&self.app_keys)?;

        let mut notifications = self.pool.notifications();

        // Send request
        self.pool.send_event(event).await?;

        time::timeout(Some(self.timeout), async {
            while let Ok(notification) = notifications.recv().await {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::NostrConnect {
                        let msg = nip04::decrypt(secret_key, &event.pubkey, &event.content)?;
                        let msg = Message::from_json(msg)?;

                        tracing::debug!("Received NIP46 message: '{msg}'");

                        if let Message::Response { id, result, error } = &msg {
                            if &req_id == id {
                                if msg.is_auth_url() {
                                    if let Some(str) = error {
                                        if let Ok(url) = Url::parse(str) {
                                            let _ = webbrowser::open(url.as_str());
                                        }
                                    }
                                    tracing::warn!("Received 'auth_url': {error:?}");
                                } else {
                                    if let Some(result) = result {
                                        return Ok(result.clone());
                                    }

                                    if let Some(error) = error {
                                        return Err(Error::Response(error.to_owned()));
                                    }

                                    break;
                                }
                            }
                        }
                    }
                }
            }

            Err(Error::Timeout)
        })
        .await
        .ok_or(Error::Timeout)?
    }

    /// Connect msg
    async fn connect(&self, remote_signer_public_key: PublicKey) -> Result<(), Error> {
        let req = Request::Connect {
            public_key: remote_signer_public_key,
            secret: self.secret.clone(),
        };
        let res = self
            .send_request_with_pk(req, remote_signer_public_key)
            .await?;
        Ok(res.to_connect()?)
    }

    /// Sign an [UnsignedEvent]
    pub async fn get_relays(&self) -> Result<HashMap<Url, RelayPermissions>, Error> {
        let req = Request::GetRelays;
        let res = self.send_request(req).await?;
        Ok(res.to_get_relays()?)
    }

    async fn _get_public_key(&self) -> Result<&PublicKey, Error> {
        self.user_public_key
            .get_or_try_init(|| async {
                let res = self.send_request(Request::GetPublicKey).await?;
                Ok(res.to_get_public_key()?)
            })
            .await
    }

    /// Sign an [UnsignedEvent]
    async fn _sign_event(&self, unsigned: UnsignedEvent) -> Result<Event, Error> {
        let req = Request::SignEvent(unsigned);
        let res = self.send_request(req).await?;
        Ok(res.to_sign_event()?)
    }

    async fn _nip04_encrypt(
        &self,
        public_key: PublicKey,
        content: String,
    ) -> Result<String, Error> {
        let req = Request::Nip04Encrypt {
            public_key,
            text: content,
        };
        let res = self.send_request(req).await?;
        Ok(res.to_encrypt_decrypt()?)
    }

    async fn _nip04_decrypt(
        &self,
        public_key: PublicKey,
        ciphertext: String,
    ) -> Result<String, Error> {
        let req = Request::Nip04Decrypt {
            public_key,
            ciphertext,
        };
        let res = self.send_request(req).await?;
        Ok(res.to_encrypt_decrypt()?)
    }

    async fn _nip44_encrypt(
        &self,
        public_key: PublicKey,
        content: String,
    ) -> Result<String, Error> {
        let req = Request::Nip44Encrypt {
            public_key,
            text: content,
        };
        let res = self.send_request(req).await?;
        Ok(res.to_encrypt_decrypt()?)
    }

    async fn _nip44_decrypt(
        &self,
        public_key: PublicKey,
        payload: String,
    ) -> Result<String, Error> {
        let req = Request::Nip44Decrypt {
            public_key,
            ciphertext: payload,
        };
        let res = self.send_request(req).await?;
        Ok(res.to_encrypt_decrypt()?)
    }

    /// Completely shutdown
    pub async fn shutdown(self) -> Result<(), Error> {
        Ok(self.pool.shutdown().await?)
    }
}

enum GetRemoteSignerPublicKey {
    WithUserPublicKey { remote: PublicKey, user: PublicKey },
    RemoteOnly(PublicKey),
}

async fn get_remote_signer_public_key(
    app_keys: &Keys,
    mut notifications: Receiver<RelayPoolNotification>,
    timeout: Duration,
) -> Result<GetRemoteSignerPublicKey, Error> {
    time::timeout(Some(timeout), async {
        while let Ok(notification) = notifications.recv().await {
            if let RelayPoolNotification::Event { event, .. } = notification {
                if event.kind == Kind::NostrConnect {
                    // Decrypt content
                    let msg: String =
                        nip04::decrypt(app_keys.secret_key(), &event.pubkey, event.content)?;

                    tracing::debug!("Received Nostr Connect message: '{msg}'");

                    // Parse message
                    let msg: Message = Message::from_json(msg)?;

                    // Match message
                    match msg {
                        Message::Request {
                            req: Request::Connect { public_key, .. },
                            ..
                        } => {
                            return Ok(GetRemoteSignerPublicKey::WithUserPublicKey {
                                remote: event.pubkey,
                                user: public_key,
                            });
                        }
                        Message::Response {
                            result: Some(ResponseResult::Connect),
                            error: None,
                            ..
                        } => return Ok(GetRemoteSignerPublicKey::RemoteOnly(event.pubkey)),
                        _ => {}
                    }
                }
            }
        }

        Err(Error::SignerPublicKeyNotFound)
    })
    .await
    .ok_or(Error::Timeout)?
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NostrSigner for NostrConnect {
    async fn get_public_key(&self) -> Result<PublicKey, SignerError> {
        self._get_public_key()
            .await
            .copied()
            .map_err(SignerError::backend)
    }

    async fn sign_event(&self, unsigned: UnsignedEvent) -> Result<Event, SignerError> {
        self._sign_event(unsigned)
            .await
            .map_err(SignerError::backend)
    }

    async fn nip04_encrypt(
        &self,
        public_key: &PublicKey,
        content: &str,
    ) -> Result<String, SignerError> {
        self._nip04_encrypt(*public_key, content.to_string())
            .await
            .map_err(SignerError::backend)
    }

    async fn nip04_decrypt(
        &self,
        public_key: &PublicKey,
        content: &str,
    ) -> Result<String, SignerError> {
        self._nip04_decrypt(*public_key, content.to_string())
            .await
            .map_err(SignerError::backend)
    }

    async fn nip44_encrypt(
        &self,
        public_key: &PublicKey,
        content: &str,
    ) -> Result<String, SignerError> {
        self._nip44_encrypt(*public_key, content.to_string())
            .await
            .map_err(SignerError::backend)
    }

    async fn nip44_decrypt(
        &self,
        public_key: &PublicKey,
        content: &str,
    ) -> Result<String, SignerError> {
        self._nip44_decrypt(*public_key, content.to_string())
            .await
            .map_err(SignerError::backend)
    }
}
