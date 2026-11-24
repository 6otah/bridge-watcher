//! CCTP V2 message header and BurnMessageV2 body codec.
//!
//! Header layout (big-endian): version u32 @0, source domain @4, destination
//! domain @8, nonce b32 @12, sender b32 @44, recipient b32 @76, destination
//! caller b32 @108, min finality threshold u32 @140, finality threshold
//! executed u32 @144, body @148.
//!
//! Body layout: version u32 @0, burn token @4, mint recipient @36, amount u256
//! @68, message sender @100, max fee u256 @132, fee executed u256 @164,
//! expiration block u256 @196, hook data @228 to the end.

use crate::codec::CodecError;
use crate::domain::{BurnBody, BurnMessage, Bytes32, Domain, IrisFields, ReceiveMessage};

const HEADER_LEN: usize = 148;
const BODY_FIXED_LEN: usize = 228;

/// Decoded fixed part of a CCTP V2 message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageHeader {
    /// Header version; always 1 after a successful decode.
    pub version: u32,
    /// Chain of the burn.
    pub source_domain: Domain,
    /// Chain of the mint.
    pub destination_domain: Domain,
    /// Nonce; zero on the source chain.
    pub nonce: Bytes32,
    /// Source token messenger.
    pub sender: Bytes32,
    /// Destination token messenger.
    pub recipient: Bytes32,
    /// Required relayer; zero means anyone.
    pub destination_caller: Bytes32,
    /// Finality the burner asked for.
    pub min_finality_threshold: u32,
    /// Finality used; zero on the source chain.
    pub finality_threshold_executed: u32,
}

fn be_u32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().expect("slice of 4"))
}

fn b32(b: &[u8], at: usize) -> Bytes32 {
    Bytes32(b[at..at + 32].try_into().expect("slice of 32"))
}

/// Reads a u256 word that must fit in `i64`; returns it as `u64`.
fn u256_as_i64(b: &[u8], at: usize, field: &'static str) -> Result<u64, CodecError> {
    let word = &b[at..at + 32];
    if word[..24].iter().any(|x| *x != 0) {
        return Err(CodecError::Overflow { field });
    }
    let v = u64::from_be_bytes(word[24..].try_into().expect("slice of 8"));
    if v > i64::MAX as u64 {
        return Err(CodecError::Overflow { field });
    }
    Ok(v)
}

/// Decodes the header only. Lets callers skip messages of other domains or
/// senders cheaply.
///
/// # Errors
/// [`CodecError::TooShort`] below 148 bytes; [`CodecError::BadVersion`] if the
/// header version is not 1.
pub fn decode_header(msg: &[u8]) -> Result<MessageHeader, CodecError> {
    if msg.len() < HEADER_LEN {
        return Err(CodecError::TooShort {
            what: "message header",
            len: msg.len(),
            min: HEADER_LEN,
        });
    }
    let version = be_u32(msg, 0);
    if version != 1 {
        return Err(CodecError::BadVersion {
            what: "message header",
            found: version,
        });
    }
    Ok(MessageHeader {
        version,
        source_domain: Domain(be_u32(msg, 4)),
        destination_domain: Domain(be_u32(msg, 8)),
        nonce: b32(msg, 12),
        sender: b32(msg, 44),
        recipient: b32(msg, 76),
        destination_caller: b32(msg, 108),
        min_finality_threshold: be_u32(msg, 140),
        finality_threshold_executed: be_u32(msg, 144),
    })
}

/// Decodes a BurnMessageV2 body.
///
/// # Errors
/// [`CodecError::TooShort`] below 228 bytes; [`CodecError::BadVersion`] if the
/// body version is not 1; [`CodecError::Overflow`] if `amount`, `max_fee`,
/// `fee_executed` or `expiration_block` exceeds `i64::MAX`.
pub fn decode_burn_body(body: &[u8]) -> Result<BurnBody, CodecError> {
    if body.len() < BODY_FIXED_LEN {
        return Err(CodecError::TooShort {
            what: "burn message body",
            len: body.len(),
            min: BODY_FIXED_LEN,
        });
    }
    let version = be_u32(body, 0);
    if version != 1 {
        return Err(CodecError::BadVersion {
            what: "burn message body",
            found: version,
        });
    }
    Ok(BurnBody {
        burn_token: b32(body, 4),
        mint_recipient: b32(body, 36),
        amount: u256_as_i64(body, 68, "amount")?,
        depositor: b32(body, 100),
        max_fee: u256_as_i64(body, 132, "max_fee")?,
        fee_executed: u256_as_i64(body, 164, "fee_executed")?,
        expiration_block: u256_as_i64(body, 196, "expiration_block")?,
        hook_data: body[BODY_FIXED_LEN..].to_vec(),
    })
}

/// Decodes a full message with a burn body into the source-written part and
/// the Iris-filled part.
///
/// # Errors
/// Any error of [`decode_header`] or [`decode_burn_body`].
pub fn decode_burn_message(msg: &[u8]) -> Result<(BurnMessage, IrisFields), CodecError> {
    let header = decode_header(msg)?;
    let body = decode_burn_body(&msg[HEADER_LEN..])?;
    Ok(split_burn(header, body))
}

fn split_burn(header: MessageHeader, body: BurnBody) -> (BurnMessage, IrisFields) {
    let iris = IrisFields {
        nonce: header.nonce,
        finality_threshold_executed: header.finality_threshold_executed,
        fee_executed: body.fee_executed,
        expiration_block: body.expiration_block,
    };
    let burn = BurnMessage {
        source_domain: header.source_domain,
        destination_domain: header.destination_domain,
        sender: header.sender,
        recipient: header.recipient,
        destination_caller: header.destination_caller,
        min_finality_threshold: header.min_finality_threshold,
        burn_token: body.burn_token,
        mint_recipient: body.mint_recipient,
        amount: body.amount,
        depositor: body.depositor,
        max_fee: body.max_fee,
        hook_data: body.hook_data,
    };
    (burn, iris)
}

/// The pieces of a receive that a destination chain exposes next to the raw
/// body.
pub struct ReceiveFields<'a> {
    /// Chain of the burn.
    pub source_domain: Domain,
    /// Nonce assigned by Iris.
    pub nonce: Bytes32,
    /// Source token messenger.
    pub sender: Bytes32,
    /// Account that relayed the message.
    pub caller: Bytes32,
    /// Finality actually used.
    pub finality_threshold_executed: u32,
    /// Raw BurnMessageV2 body.
    pub message_body: &'a [u8],
}

/// Builds a [`ReceiveMessage`] by decoding the raw body of `fields`.
///
/// # Errors
/// Any error of [`decode_burn_body`].
pub fn decode_receive(fields: ReceiveFields<'_>) -> Result<ReceiveMessage, CodecError> {
    Ok(ReceiveMessage {
        source_domain: fields.source_domain,
        nonce: fields.nonce,
        sender: fields.sender,
        caller: fields.caller,
        finality_threshold_executed: fields.finality_threshold_executed,
        body: decode_burn_body(fields.message_body)?,
    })
}
