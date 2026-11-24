//! Anchor `emit_cpi!` events of the CCTP V2 Solana programs.
//!
//! An event is an inner instruction whose data is `EVENT_IX_TAG` + an 8-byte
//! event discriminator + the Borsh payload. This module only decodes bytes. The
//! caller must also check that the transaction succeeded, that the instruction
//! is an inner instruction, and that its program id is the CCTP program: other
//! programs (for example an aggregator) emit events with the same tag.

use borsh::BorshDeserialize;

use crate::codec::{CodecError, ReceiveFields, decode_receive};
use crate::domain::{BurnMessage, Bytes32, Domain, ReceiveMessage};

/// Prefix of every Anchor event instruction.
pub const EVENT_IX_TAG: [u8; 8] = [0xe4, 0x45, 0xa5, 0x2e, 0x51, 0xcb, 0x9a, 0x1d];
/// Discriminator of `DepositForBurn` (`sha256("event:DepositForBurn")[..8]`).
pub const DEPOSIT_FOR_BURN: [u8; 8] = [0x90, 0xfc, 0x91, 0x92, 0x06, 0x4a, 0xa7, 0xeb];
/// Discriminator of `MessageReceived` (`sha256("event:MessageReceived")[..8]`).
pub const MESSAGE_RECEIVED: [u8; 8] = [0xe7, 0x44, 0x2f, 0x4d, 0xad, 0xf1, 0x9d, 0xa6];

/// Returns `(discriminator, Borsh payload)` if `data` starts with
/// [`EVENT_IX_TAG`] and holds a full discriminator.
pub fn split_event_ix(data: &[u8]) -> Option<([u8; 8], &[u8])> {
    let rest = data.strip_prefix(&EVENT_IX_TAG)?;
    let (disc, payload) = rest.split_first_chunk::<8>()?;
    Some((*disc, payload))
}

/// `DepositForBurn` event of TokenMessengerMinterV2, in Borsh field order.
#[derive(BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct DepositForBurnEvent {
    /// Token mint that was burned.
    pub burn_token: [u8; 32],
    /// Gross amount.
    pub amount: u64,
    /// Account that burned.
    pub depositor: [u8; 32],
    /// Recipient on the destination chain.
    pub mint_recipient: [u8; 32],
    /// Destination domain.
    pub destination_domain: u32,
    /// Token messenger on the destination chain.
    pub destination_token_messenger: [u8; 32],
    /// Required relayer on the destination chain.
    pub destination_caller: [u8; 32],
    /// Maximum fee accepted.
    pub max_fee: u64,
    /// Finality the burner asked for.
    pub min_finality_threshold: u32,
    /// Hook payload.
    pub hook_data: Vec<u8>,
}

/// `MessageReceived` event of MessageTransmitterV2, in Borsh field order.
#[derive(BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct MessageReceivedEvent {
    /// Account that relayed the message.
    pub caller: [u8; 32],
    /// Domain of the burn.
    pub source_domain: u32,
    /// Nonce assigned by Iris.
    pub nonce: [u8; 32],
    /// Source token messenger.
    pub sender: [u8; 32],
    /// Finality used.
    pub finality_threshold_executed: u32,
    /// BurnMessageV2 body.
    pub message_body: Vec<u8>,
}

fn check_i64(v: u64, field: &'static str) -> Result<u64, CodecError> {
    if v > i64::MAX as u64 {
        Err(CodecError::Overflow { field })
    } else {
        Ok(v)
    }
}

impl DepositForBurnEvent {
    /// Decodes the Borsh payload exactly: trailing bytes are an error.
    ///
    /// # Errors
    /// [`CodecError::Borsh`] on bad or trailing bytes.
    pub fn decode(payload: &[u8]) -> Result<Self, CodecError> {
        Self::try_from_slice(payload).map_err(|e| CodecError::Borsh(e.to_string()))
    }

    /// Builds the source-written burn content. `sender` is the token
    /// messenger program (the Iris message `sender`); `recipient` is the
    /// destination token messenger carried by the event.
    ///
    /// # Errors
    /// [`CodecError::Overflow`] if `amount` or `max_fee` exceeds `i64::MAX`.
    pub fn into_burn_message(
        self,
        source_domain: Domain,
        token_messenger_minter: Bytes32,
    ) -> Result<BurnMessage, CodecError> {
        Ok(BurnMessage {
            source_domain,
            destination_domain: Domain(self.destination_domain),
            sender: token_messenger_minter,
            recipient: Bytes32(self.destination_token_messenger),
            destination_caller: Bytes32(self.destination_caller),
            min_finality_threshold: self.min_finality_threshold,
            burn_token: Bytes32(self.burn_token),
            mint_recipient: Bytes32(self.mint_recipient),
            amount: check_i64(self.amount, "amount")?,
            depositor: Bytes32(self.depositor),
            max_fee: check_i64(self.max_fee, "max_fee")?,
            hook_data: self.hook_data,
        })
    }
}

impl MessageReceivedEvent {
    /// Decodes the Borsh payload exactly: trailing bytes are an error.
    ///
    /// # Errors
    /// [`CodecError::Borsh`] on bad or trailing bytes.
    pub fn decode(payload: &[u8]) -> Result<Self, CodecError> {
        Self::try_from_slice(payload).map_err(|e| CodecError::Borsh(e.to_string()))
    }

    /// Decodes the embedded body and builds the receive.
    ///
    /// # Errors
    /// Any error of [`crate::codec::decode_burn_body`].
    pub fn into_receive_message(self) -> Result<ReceiveMessage, CodecError> {
        decode_receive(ReceiveFields {
            source_domain: Domain(self.source_domain),
            nonce: Bytes32(self.nonce),
            sender: Bytes32(self.sender),
            caller: Bytes32(self.caller),
            finality_threshold_executed: self.finality_threshold_executed,
            message_body: &self.message_body,
        })
    }
}
