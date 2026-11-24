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

/// One flattened inner instruction of a Solana transaction.
pub struct InnerIx {
    /// Position in the flattened inner-instruction list.
    pub index: u32,
    /// Index into the account keys (static + loaded writable + loaded readonly).
    pub program_index: usize,
    pub program_id: String,
    pub data: Vec<u8>,
}

/// Account keys as the runtime resolves them for a v0 or v1 transaction.
pub fn account_keys(tx: &Value) -> Vec<String> {
    let strings = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|a| a.iter().map(|k| k.as_str().unwrap().to_string()).collect())
            .unwrap_or_default()
    };
    let mut keys = strings(&tx["transaction"]["message"]["accountKeys"]);
    let loaded = &tx["meta"]["loadedAddresses"];
    keys.extend(strings(&loaded["writable"]));
    keys.extend(strings(&loaded["readonly"]));
    keys
}

pub fn static_key_count(tx: &Value) -> usize {
    tx["transaction"]["message"]["accountKeys"]
        .as_array()
        .unwrap()
        .len()
}

pub fn inner_instructions(tx: &Value) -> Vec<InnerIx> {
    let keys = account_keys(tx);
    let mut out = Vec::new();
    let mut index = 0u32;
    for group in tx["meta"]["innerInstructions"].as_array().unwrap() {
        for ix in group["instructions"].as_array().unwrap() {
            let program_index = ix["programIdIndex"].as_u64().unwrap() as usize;
            out.push(InnerIx {
                index,
                program_index,
                program_id: keys[program_index].clone(),
                data: bs58::decode(ix["data"].as_str().unwrap())
                    .into_vec()
                    .unwrap(),
            });
            index += 1;
        }
    }
    out
}
