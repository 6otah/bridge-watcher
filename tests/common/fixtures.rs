//! Loaders for the real mainnet captures in `tests/fixtures/`.

use std::path::PathBuf;

use alloy::rpc::types::Log;
use alloy::sol;
use alloy::sol_types::SolEvent;
use serde_json::Value;

sol! {
    event MessageSent(bytes message);
    event MessageReceived(
        address indexed caller,
        uint32 sourceDomain,
        bytes32 indexed nonce,
        bytes32 sender,
        uint32 indexed finalityThresholdExecuted,
        bytes messageBody
    );
}

pub fn read(name: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", name]
        .iter()
        .collect();
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

pub fn json(name: &str) -> Value {
    serde_json::from_str(&read(name)).expect("fixture is JSON")
}

/// The fixture JSON has fields alloy does not model (`blockTimestampMs`).
pub fn log(name: &str) -> Log {
    serde_json::from_str(&read(name)).expect("alloy Log deserializes the fixture")
}

pub fn base_burn_log() -> Log {
    log("base_burn_to_solana.log.json")
}

pub fn base_receive_log() -> Log {
    log("base_receive_from_solana.log.json")
}

/// The `bytes message` argument of the fixture `MessageSent` log.
pub fn message_sent_bytes(log: &Log) -> Vec<u8> {
    let ev = MessageSent::decode_raw_log(log.topics(), &log.data().data).expect("MessageSent");
    ev.message.to_vec()
}

pub fn message_received(log: &Log) -> MessageReceived {
    MessageReceived::decode_raw_log(log.topics(), &log.data().data).expect("MessageReceived")
}

/// `messages[0].message` of an Iris fixture, as bytes.
pub fn iris_message(name: &str) -> Vec<u8> {
    let v = json(name);
    let hex_str = v["messages"][0]["message"].as_str().expect("message");
    hex::decode(hex_str.trim_start_matches("0x")).expect("hex")
}

/// One flattened inner instruction of a Solana transaction. Program ids are
/// not resolved here: that is the trust rule of `events_from_transaction`, and
/// a second copy in test code could drift from it.
pub struct InnerIx {
    /// Position in the flattened inner-instruction list.
    pub index: u32,
    pub data: Vec<u8>,
}

pub fn inner_instructions(tx: &Value) -> Vec<InnerIx> {
    let mut out = Vec::new();
    let mut index = 0u32;
    for group in tx["meta"]["innerInstructions"].as_array().unwrap() {
        for ix in group["instructions"].as_array().unwrap() {
            out.push(InnerIx {
                index,
                data: bs58::decode(ix["data"].as_str().unwrap())
                    .into_vec()
                    .unwrap(),
            });
            index += 1;
        }
    }
    out
}
