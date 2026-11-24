//! Byte-level decoding of CCTP V2 data. Pure: no I/O.
//!
//! - [`message`]: the CCTP V2 message header and the BurnMessageV2 body. One
//!   codec decodes EVM `MessageSent` logs, Iris messages and receive bodies.
//! - [`solana_event`]: Anchor `emit_cpi!` events of the Solana programs.
//!
//! Invariant: every decoder rejects short input and amounts above `i64::MAX`,
//! so decoded values always fit the database columns.

pub mod message;
pub mod solana_event;

pub use message::{
    MessageHeader, ReceiveFields, decode_burn_body, decode_burn_message, decode_header,
    decode_receive,
};
pub use solana_event::{
    DEPOSIT_FOR_BURN, DepositForBurnEvent, EVENT_IX_TAG, MESSAGE_RECEIVED, MessageReceivedEvent,
    split_event_ix,
};

/// Failure to decode CCTP bytes.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// The input is shorter than the fixed part of the structure.
    #[error("{what}: length {len} < minimum {min}")]
    TooShort {
        /// Structure that was being decoded.
        what: &'static str,
        /// Actual length.
        len: usize,
        /// Required length.
        min: usize,
    },
    /// A version field is not 1.
    #[error("{what}: unsupported version {found}")]
    BadVersion {
        /// Structure that was being decoded.
        what: &'static str,
        /// Version found.
        found: u32,
    },
    /// A number does not fit in `i64`.
    #[error("{field}: value does not fit in i64")]
    Overflow {
        /// Field name.
        field: &'static str,
    },
    /// Text is not base58 or has the wrong length.
    #[error("invalid base58")]
    BadBase58,
    /// Borsh decoding failed (including trailing bytes).
    #[error("borsh: {0}")]
    Borsh(String),
}
