//! Shared test code. Each test crate declares `mod common;` and uses a subset,
//! so unused items are expected.
#![allow(dead_code)]

pub mod fake_chain;
pub mod fake_iris;
pub mod fake_sink;
pub mod fixtures;

use bridge_watcher::domain::{
    BurnBody, BurnMessage, Bytes32, ChainEvent, Domain, EventKind, EventLocation, ReceiveMessage,
};

/// A burn on `domain` towards the other test domain, with distinct content per
/// `amount`.
pub fn burn_message(domain: u32, amount: u64) -> BurnMessage {
    BurnMessage {
        source_domain: Domain(domain),
        destination_domain: Domain(if domain == 6 { 5 } else { 6 }),
        sender: Bytes32([1; 32]),
        recipient: Bytes32([2; 32]),
        destination_caller: Bytes32::ZERO,
        min_finality_threshold: 2000,
        burn_token: Bytes32([3; 32]),
        mint_recipient: Bytes32([4; 32]),
        amount,
        depositor: Bytes32([5; 32]),
        max_fee: 0,
        hook_data: vec![],
    }
}

fn location(domain: u32, tx: &str, index: u32, height: u64) -> EventLocation {
    EventLocation {
        domain: Domain(domain),
        tx_id: tx.to_string(),
        event_index: index,
        height,
        block_hash: (domain == 6).then(|| format!("0xhash{height}")),
        block_time: 1_700_000_000 + height as i64,
    }
}

/// A burn event with a fixed body and the given location.
pub fn burn_event(domain: u32, tx: &str, index: u32, height: u64, amount: u64) -> ChainEvent {
    ChainEvent {
        at: location(domain, tx, index, height),
        kind: EventKind::Burn(burn_message(domain, amount)),
    }
}

/// A receive event on `domain` for a burn from the other test domain. The
/// nonce is `[nonce_byte; 32]`.
pub fn receive_event(
    domain: u32,
    tx: &str,
    index: u32,
    height: u64,
    nonce_byte: u8,
    amount: u64,
) -> ChainEvent {
    ChainEvent {
        at: location(domain, tx, index, height),
        kind: EventKind::Receive(ReceiveMessage {
            source_domain: Domain(if domain == 6 { 5 } else { 6 }),
            nonce: Bytes32([nonce_byte; 32]),
            sender: Bytes32([1; 32]),
            caller: Bytes32([6; 32]),
            finality_threshold_executed: 2000,
            body: BurnBody {
                burn_token: Bytes32([3; 32]),
                mint_recipient: Bytes32([4; 32]),
                amount,
                depositor: Bytes32([5; 32]),
                max_fee: 0,
                fee_executed: 0,
                expiration_block: 0,
                hook_data: vec![],
            },
        }),
    }
}
