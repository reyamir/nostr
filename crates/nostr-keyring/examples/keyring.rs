// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

use nostr_keyring::prelude::*;

fn main() {
    let mut keyring = NostrKeyring::open().unwrap();

    let keys =
        Keys::parse("nsec12kcgs78l06p30jz7z7h3n2x2cy99nw2z6zspjdp7qc206887mwvs95lnkx").unwrap();
    let account = Account::new(
        "Test",
        keys.public_key(),
        AccountSecretKey::Unencrypted(keys.secret_key().unwrap().clone()),
    );
    keyring.add_account(account).unwrap();

    // Get accounts
    for (index, account) in keyring.accounts().iter().enumerate() {
        println!("Account #{index}:");
        println!("- Name: {}", account.name());
        println!("- Public Key: {}", account.public_key());
    }
}
