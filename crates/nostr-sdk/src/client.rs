// Copyright (c) 2022 Yuki Kishimoto
// Distributed under the MIT software license

use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::Result;
use bitcoin_hashes::sha256::Hash;
use nostr_sdk_base::{Contact, Event, Keys, SubscriptionFilter, Tag};
use tokio::sync::broadcast;
use url::Url;

use crate::relay::pool::{RelayPool, RelayPoolNotifications};
#[cfg(feature = "blocking")]
use crate::RUNTIME;

pub struct Client {
    pub pool: RelayPool,
    pub keys: Keys,
}

impl Client {
    /// Create a new `Client`
    ///
    /// # Example
    /// ```rust
    /// use nostr_sdk::Client;
    ///
    /// let my_keys = Client::generate_keys();
    /// let mut client = Client::new(&my_keys);
    /// ```
    pub fn new(keys: &Keys) -> Self {
        Self {
            pool: RelayPool::new(),
            keys: keys.clone(),
        }
    }

    /// Generate new random keys using entorpy from OS
    pub fn generate_keys() -> Keys {
        Keys::generate_from_os_random()
    }

    /// Get new notification listener
    pub fn notifications(&self) -> broadcast::Receiver<RelayPoolNotifications> {
        self.pool.notifications()
    }

    /// Add new relay
    ///
    /// # Example
    /// ```rust
    /// client.add_relay("wss://relay.nostr.info", None)?;
    /// client.add_relay("wss://relay.damus.io", None)?;
    /// ```
    pub fn add_relay(&mut self, url: &str, proxy: Option<SocketAddr>) -> Result<()> {
        self.pool.add_relay(url, proxy)
    }

    /// Disconnect and remove relay
    ///
    /// # Example
    /// ```rust
    /// client.remove_relay("wss://relay.nostr.info", None).await?;
    /// ```
    #[cfg(not(feature = "blocking"))]
    pub async fn remove_relay(&mut self, url: &str) -> Result<()> {
        self.pool.remove_relay(url).await
    }

    /// Connect relay
    ///
    /// # Example
    /// ```rust
    /// client.connect_relay("wss://relay.nostr.info", None).await?;
    /// ```
    #[cfg(not(feature = "blocking"))]
    pub async fn connect_relay(&mut self, url: &str) -> Result<()> {
        self.pool.connect_relay(url).await
    }

    /// Disconnect relay
    ///
    /// # Example
    /// ```rust
    /// client.disconnect_relay("wss://relay.nostr.info", None).await?;
    /// ```
    #[cfg(not(feature = "blocking"))]
    pub async fn disconnect_relay(&mut self, url: &str) -> Result<()> {
        self.pool.disconnect_relay(url).await
    }

    /// Connect to all added relays and keep connection alive
    ///
    /// # Example
    /// ```rust
    /// client.connect().await?;
    /// ```
    #[cfg(not(feature = "blocking"))]
    pub async fn connect(&mut self) -> Result<()> {
        self.pool.connect().await
    }

    /// Disconnect from all relays
    ///
    /// # Example
    /// ```rust
    /// client.disconnect().await?;
    /// ```
    #[cfg(not(feature = "blocking"))]
    pub async fn disconnect(&mut self) -> Result<()> {
        self.pool.disconnect().await
    }

    /// Subscribe to filters
    ///
    /// # Example
    /// ```rust
    /// use nostr_sdk::base::SubscriptionFilter;
    ///
    /// let subscription = SubscriptionFilter::new()
    ///     .pubkeys(vec![my_keys.public_key()])
    ///     .since(Utc::now());
    ///
    /// client.subscribe(vec![subscription]).await?;
    /// ```
    #[cfg(not(feature = "blocking"))]
    pub async fn subscribe(&mut self, filters: Vec<SubscriptionFilter>) -> Result<()> {
        self.pool.subscribe(filters).await
    }

    /// Send event
    #[cfg(not(feature = "blocking"))]
    pub async fn send_event(&self, event: Event) -> Result<()> {
        self.pool.send_event(event).await
    }

    /// Update profile metadata
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    ///
    /// # Example
    /// ```rust
    /// client.update_profile(
    ///     Some("nostr_sdk"),
    ///     Some("Nostr SDK"),
    ///     Some("https://github.com/yukibtc/nostr-rs-sdk"),
    ///     None,
    /// )
    /// .await
    /// .unwrap();
    /// ```
    #[cfg(not(feature = "blocking"))]
    pub async fn update_profile(
        &self,
        username: Option<&str>,
        display_name: Option<&str>,
        about: Option<&str>,
        picture: Option<&str>,
    ) -> Result<()> {
        let event = Event::set_metadata(&self.keys, username, display_name, about, picture)?;
        self.send_event(event).await
    }

    /// Publish text note
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    ///
    /// # Example
    /// ```rust
    /// client.publish_text_note("My first text note from Nostr SDK!", &[]).await.unwrap();
    /// ```
    #[cfg(not(feature = "blocking"))]
    pub async fn publish_text_note(&self, content: &str, tags: &[Tag]) -> Result<()> {
        let event = Event::new_text_note(&self.keys, content, tags)?;
        self.send_event(event).await
    }

    /// Publish POW text note
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/13.md>
    ///
    /// # Example
    /// ```rust
    /// client.publish_pow_text_note("My first POW text note from Nostr SDK!", &[], 16).await.unwrap();
    /// ```
    #[cfg(not(feature = "blocking"))]
    pub async fn publish_pow_text_note(
        &self,
        content: &str,
        tags: &[Tag],
        difficulty: u8,
    ) -> Result<()> {
        let event = Event::new_pow_text_note(&self.keys, content, tags, difficulty)?;
        self.send_event(event).await
    }

    /// Add recommended relay
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    ///
    /// # Example
    /// ```rust
    /// client.add_recommended_relay("wss://relay.damus.io").await.unwrap();
    /// ```
    #[cfg(not(feature = "blocking"))]
    pub async fn add_recommended_relay(&self, url: &str) -> Result<()> {
        let url = Url::from_str(url)?;
        let event = Event::add_recommended_relay(&self.keys, &url)?;
        self.send_event(event).await
    }

    /// Set contact list
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/02.md>
    ///
    /// # Example
    /// ```rust
    /// use nostr_sdk::base::Contact;
    /// use nostr_sdk::base::key::{Keys, FromBech32};
    ///
    /// let list = vec![
    ///     Contact::new(
    ///         "my_first_contact",
    ///         Keys::from_bech32_public_key("npub1...").unwrap().public_key(),
    ///         "wss://relay.damus.io",
    ///     ),
    /// ];
    /// client.set_contact_list(list).await.unwrap();
    /// ```
    #[cfg(not(feature = "blocking"))]
    pub async fn set_contact_list(&self, list: Vec<Contact>) -> Result<()> {
        let event = Event::set_contact_list(&self.keys, list)?;
        self.send_event(event).await
    }

    /// Send encrypted direct message
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/04.md>
    ///
    /// # Example
    /// ```rust
    /// use nostr_sdk::base::key::{Keys, FromBech32};
    ///
    /// let alice_keys = Keys::from_bech32_public_key("npub1...").unwrap();
    /// client.send_direct_msg(alice_keys, "My first DM fro Nostr SDK!").await.unwrap();
    /// ```
    #[cfg(not(feature = "blocking"))]
    pub async fn send_direct_msg(&self, recipient: &Keys, msg: &str) -> Result<()> {
        let event = Event::new_encrypted_direct_msg(&self.keys, recipient, msg)?;
        self.send_event(event).await
    }

    /// Delete event
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/09.md>
    ///
    #[cfg(not(feature = "blocking"))]
    pub async fn delete_event(&self, event_id: &str) -> Result<()> {
        let event = Event::delete(&self.keys, vec![Hash::from_str(event_id)?], None)?;
        self.send_event(event).await
    }

    #[cfg(not(feature = "blocking"))]
    pub async fn handle_notifications<F>(&self, func: F) -> Result<()>
    where
        F: Fn(RelayPoolNotifications) -> Result<()>,
    {
        loop {
            let mut notifications = self.notifications();

            while let Ok(notification) = notifications.recv().await {
                func(notification)?;
            }
        }
    }
}

#[allow(missing_docs)]
#[cfg(feature = "blocking")]
impl Client {
    pub fn remove_relay(&mut self, url: &str) -> Result<()> {
        RUNTIME.block_on(async { self.pool.remove_relay(url).await })
    }

    pub fn connect_relay(&mut self, url: &str) -> Result<()> {
        RUNTIME.block_on(async { self.pool.connect_relay(url).await })
    }

    pub fn disconnect_relay(&mut self, url: &str) -> Result<()> {
        RUNTIME.block_on(async { self.pool.disconnect_relay(url).await })
    }

    pub fn connect(&mut self) -> Result<()> {
        RUNTIME.block_on(async { self.pool.connect().await })
    }

    pub fn disconnect(&mut self) -> Result<()> {
        RUNTIME.block_on(async { self.pool.disconnect().await })
    }

    pub fn subscribe(&mut self, filters: Vec<SubscriptionFilter>) -> Result<()> {
        RUNTIME.block_on(async { self.pool.subscribe(filters).await })
    }

    pub fn send_event(&self, event: Event) -> Result<()> {
        RUNTIME.block_on(async { self.pool.send_event(event).await })
    }

    pub fn update_profile(
        &self,
        username: Option<&str>,
        display_name: Option<&str>,
        about: Option<&str>,
        picture: Option<&str>,
    ) -> Result<()> {
        let event = Event::set_metadata(&self.keys, username, display_name, about, picture)?;
        self.send_event(event)
    }

    pub fn publish_text_note(&self, content: &str, tags: &[Tag]) -> Result<()> {
        let event = Event::new_text_note(&self.keys, content, tags)?;
        self.send_event(event)
    }

    pub fn delete_event(&self, event_id: &str) -> Result<()> {
        let event = Event::delete(&self.keys, vec![Hash::from_str(event_id)?], None)?;
        self.send_event(event)
    }

    pub fn handle_notifications<F>(&self, func: F) -> Result<()>
    where
        F: Fn(RelayPoolNotifications) -> Result<()>,
    {
        RUNTIME.block_on(async {
            loop {
                let mut notifications = self.notifications();

                while let Ok(notification) = notifications.recv().await {
                    func(notification)?;
                }
            }
        })
    }
}
