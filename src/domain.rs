//! Plain data types shared by all modules. No I/O.
//!
//! Invariant: [`BurnMessage`] holds only fields that the source chain writes.
//! Fields that Circle Iris fills at attestation time live in [`IrisFields`],
//! so two `BurnMessage` values are equal exactly when they describe the same
//! burn content.

use std::fmt;

use crate::codec::CodecError;

/// CCTP domain id. Solana = 5, Base = 6. Used as the chain key everywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Domain(pub u32);

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// 32 raw bytes: EVM addresses left-padded with zeros, Solana pubkeys as-is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Bytes32(pub [u8; 32]);

impl Bytes32 {
    /// All zero bytes.
    pub const ZERO: Bytes32 = Bytes32([0; 32]);

    /// Left-pads a 20-byte EVM address with 12 zero bytes.
    pub fn from_evm_address(a: [u8; 20]) -> Bytes32 {
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(&a);
        Bytes32(out)
    }

    /// Parses a base58 Solana public key.
    ///
    /// # Errors
    /// [`CodecError::BadBase58`] if the text is not base58 or does not decode
    /// to exactly 32 bytes.
    pub fn from_base58(s: &str) -> Result<Bytes32, CodecError> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|_| CodecError::BadBase58)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| CodecError::BadBase58)?;
        Ok(Bytes32(arr))
    }

    /// Base58 text of the 32 bytes (the Solana public key form).
    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    /// `"0x"` followed by 64 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

impl fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// How final a scan must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commitment {
    /// Finalized chain data only.
    Finalized,
    /// Confirmed chain data (the unfinalized tail).
    Confirmed,
}

/// Transfer speed class, derived from the burn's `min_finality_threshold`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Threshold below 2000.
    Fast,
    /// Threshold of 2000 (finalized).
    Standard,
}

/// Heights read from a node at one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Heights {
    /// Highest finalized height (Solana: minus the configured margin).
    pub finalized: u64,
    /// Head height.
    pub head: u64,
}

/// Where an event sits on its chain. Identity is `(domain, tx_id, event_index)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventLocation {
    /// Chain that holds the event.
    pub domain: Domain,
    /// EVM: `"0x"` + lowercase tx hash. Solana: base58 first signature.
    pub tx_id: String,
    /// EVM: block-level logIndex. Solana: position in the flattened inner-instruction list.
    pub event_index: u32,
    /// EVM block number or Solana slot.
    pub height: u64,
    /// EVM block hash (`"0x..."`); `None` on Solana.
    pub block_hash: Option<String>,
    /// Unix seconds from the chain. Always present: adapters must fill it.
    pub block_time: i64,
}

/// Fields that the source chain writes. Equality of two values means
/// "same burn content". Iris-filled fields are absent by design.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnMessage {
    /// Chain of the burn.
    pub source_domain: Domain,
    /// Chain of the mint.
    pub destination_domain: Domain,
    /// Source token messenger.
    pub sender: Bytes32,
    /// Destination token messenger.
    pub recipient: Bytes32,
    /// Only this address may relay the message; zero means anyone.
    pub destination_caller: Bytes32,
    /// Finality the burner asked for (1000 fast, 2000 standard).
    pub min_finality_threshold: u32,
    /// Token burned on the source chain.
    pub burn_token: Bytes32,
    /// Who receives the minted tokens.
    pub mint_recipient: Bytes32,
    /// Gross amount; the decoder rejects values above `i64::MAX`.
    pub amount: u64,
    /// `BurnMessageV2.messageSender`.
    pub depositor: Bytes32,
    /// Maximum fee the burner accepts; the decoder rejects values above `i64::MAX`.
    pub max_fee: u64,
    /// Opaque hook payload.
    pub hook_data: Vec<u8>,
}

/// Fields that Circle Iris fills at attestation time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrisFields {
    /// Message nonce. Zero on the source chain; zero means "not assigned".
    pub nonce: Bytes32,
    /// Finality actually used.
    pub finality_threshold_executed: u32,
    /// Fee charged.
    pub fee_executed: u64,
    /// Expiration block of a Fast message; 0 for Standard.
    pub expiration_block: u64,
}

/// BurnMessageV2 body as seen on the destination chain (Iris fields are set).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnBody {
    /// Token burned on the source chain.
    pub burn_token: Bytes32,
    /// Who receives the minted tokens.
    pub mint_recipient: Bytes32,
    /// Gross amount.
    pub amount: u64,
    /// `BurnMessageV2.messageSender`.
    pub depositor: Bytes32,
    /// Maximum fee the burner accepted.
    pub max_fee: u64,
    /// Fee charged; the mint is `amount - fee_executed`.
    pub fee_executed: u64,
    /// Expiration block of a Fast message.
    pub expiration_block: u64,
    /// Opaque hook payload.
    pub hook_data: Vec<u8>,
}

/// A `MessageReceived` event on the destination chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveMessage {
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
    /// Decoded burn body.
    pub body: BurnBody,
}

/// Kind and payload of a relevant event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// Source-side deposit.
    Burn(BurnMessage),
    /// Destination-side receive.
    Receive(ReceiveMessage),
}

/// One relevant CCTP event with its location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainEvent {
    /// Where the event is.
    pub at: EventLocation,
    /// What the event is.
    pub kind: EventKind,
}

/// Facts about the other chain of the pair. Built from config by `app`.
#[derive(Clone, Copy, Debug)]
pub struct Counterparty {
    /// Domain of the other chain.
    pub domain: Domain,
    /// Token messenger of the other chain, as 32 bytes.
    pub token_messenger: Bytes32,
}
