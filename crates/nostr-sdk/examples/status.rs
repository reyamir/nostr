// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use nips::nip38::Statuses;
use nostr_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let keys = Keys::parse("nsec1ufnus6pju578ste3v90xd5m2decpuzpql2295m3sknqcjzyys9ls0qlc85")?;
    let client = Client::new(keys);

    client.add_relay("wss://relay.damus.io").await?;
    client.add_relay("wss://nostr.wine").await?;
    client.add_relay("wss://relay.rip").await?;

    client.connect().await;

    // Send a General statuses event to relays
    let builder =
        EventBuilder::live_statuses("Building rust-nostr", Statuses::General, None, vec![]);
    client.send_event_builder(builder).await?;

    // Send a Music statuses event to relays
    let builder = EventBuilder::live_statuses(
        "Intergalatic - Beastie Boys",
        Statuses::Music,
        Some(Timestamp::now()),
        vec![Tag::from_standardized_without_cell(TagStandard::Reference(
            "spotify:search:Intergalatic%20-%20Beastie%20Boys".into(),
        ))],
    );
    client.send_event_builder(builder).await?;

    // Send a Custom statuses event to relays
    let builder =
        EventBuilder::live_statuses("Custom", Statuses::Custom("Working".into()), None, vec![]);
    client.send_event_builder(builder).await?;

    Ok(())
}
