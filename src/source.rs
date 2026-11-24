//! Chain access contract: [`ChainSource`], [`TxInspector`], [`ScanResult`],
//! [`SourceError`] and the [`Chains`] router.
//!
//! Scan contract (`docs/ARCHITECTURE.md` section 6.3). For
//! `scan(after, up_to, commitment)`:
//!
//! - S1 Range: `after < complete_through <= up_to`, and every event has
//!   `after < height <= complete_through`.
//! - S2 Completeness: the result holds every relevant event in
//!   `(after, complete_through]` as the node sees it at `commitment`.
//! - S3 Finality: with `Commitment::Finalized`, every returned event is final
//!   and the node had reached `up_to` at finalized commitment.
//! - S4 Relevance: only burns from this chain to the counterparty via the
//!   configured token messenger, and only receives from the counterparty
//!   whose sender is the counterparty token messenger.
//!
//! A source may return less than the full range; the caller scans again.

use std::sync::Arc;

use crate::domain::{BurnMessage, ChainEvent, Commitment, Domain, Heights};

/// Result of one [`ChainSource::scan`].
#[derive(Debug)]
pub struct ScanResult {
    /// Relevant events found.
    pub events: Vec<ChainEvent>,
    /// The scan is complete for `(after, complete_through]`, with
    /// `after < complete_through <= up_to`.
    pub complete_through: u64,
}

/// Failure of a chain source. None of these is fatal for the process.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// Network error, HTTP status, JSON-RPC error, timeout, unexpected shape.
    /// The message must already be redacted.
    #[error("rpc: {0}")]
    Rpc(String),
    /// The node has not reached the requested height or commitment yet.
    #[error("node lagging: {0}")]
    Lagging(String),
    /// A CCTP event passed the identity filter but did not decode.
    #[error("undecodable CCTP event in {tx_id}: {reason}")]
    Undecodable {
        /// Transaction that holds the event.
        tx_id: String,
        /// Decoder message.
        reason: String,
    },
}

/// Read access to one chain.
///
/// Every method returns `impl Future + Send` so that tasks using the trait can
/// be spawned. Implementations may write `async fn`.
pub trait ChainSource: Send + Sync + 'static {
    /// CCTP domain of this chain.
    fn domain(&self) -> Domain;
    /// Config name of this chain, for logs.
    fn name(&self) -> &str;
    /// Finalized height and head height, read now.
    ///
    /// # Errors
    /// [`SourceError::Rpc`] if the node cannot answer.
    fn heights(&self) -> impl Future<Output = Result<Heights, SourceError>> + Send;
    /// Scans `(after, up_to]` at `commitment`. See the module docs for the
    /// contract. Precondition: `after < up_to`.
    ///
    /// # Errors
    /// [`SourceError::Rpc`], [`SourceError::Lagging`] or
    /// [`SourceError::Undecodable`].
    fn scan(
        &self,
        after: u64,
        up_to: u64,
        commitment: Commitment,
    ) -> impl Future<Output = Result<ScanResult, SourceError>> + Send;
    /// What this chain says about one transaction (orphan verification,
    /// design section 7.2). `Ok(None)`: the chain does not know the tx
    /// (Solana: it is not finalized either, or the id is not a signature).
    ///
    /// # Errors
    /// [`SourceError::Rpc`] if the node cannot answer;
    /// [`SourceError::Undecodable`] if a CCTP log of the tx does not decode.
    fn inspect_tx(
        &self,
        tx_id: &str,
    ) -> impl Future<Output = Result<Option<TxEvidence>, SourceError>> + Send;
    /// Chain time of the last existing block at or below `height`: returns
    /// `(block height, unix seconds)`. Used once, by `init_cursor`, to record
    /// `chain_state.start_time` (coverage rule, ADR 0013).
    ///
    /// EVM: the header timestamp of `height`. Solana: `getBlockTime(slot)`;
    /// on a skipped slot or a null answer it steps down one slot, at most 1000
    /// steps.
    ///
    /// # Errors
    /// [`SourceError::Rpc`] if the node cannot answer;
    /// [`SourceError::Lagging`] if no block time was found in range.
    fn time_at_or_before(
        &self,
        height: u64,
    ) -> impl Future<Output = Result<(u64, i64), SourceError>> + Send;
}

/// The source chain's view of one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxEvidence {
    /// Block number or slot of the transaction.
    pub height: u64,
    /// Burns of this tx to the counterparty domain, decoded with the same
    /// rules as ingestion (S4). Empty for a failed tx or a tx without such
    /// burns.
    pub burns: Vec<BurnMessage>,
}

/// Inspects a transaction on whichever chain owns the domain. Used by the
/// resolver to verify orphan receives against the source chain.
pub trait TxInspector: Send + Sync + 'static {
    /// Evidence for `tx_id` on the chain of `domain`; `None` if the chain does
    /// not know it or if no chain has that domain.
    ///
    /// # Errors
    /// [`SourceError`] as for [`ChainSource::inspect_tx`].
    fn inspect_tx(
        &self,
        domain: Domain,
        tx_id: &str,
    ) -> impl Future<Output = Result<Option<TxEvidence>, SourceError>> + Send;
}

/// Routes `inspect_tx` by domain to one of two sources. An unknown domain gives
/// `Ok(None)`.
pub struct Chains<A, B> {
    /// First chain.
    pub a: Arc<A>,
    /// Second chain.
    pub b: Arc<B>,
}

impl<A: ChainSource, B: ChainSource> TxInspector for Chains<A, B> {
    async fn inspect_tx(
        &self,
        domain: Domain,
        tx_id: &str,
    ) -> Result<Option<TxEvidence>, SourceError> {
        if domain == self.a.domain() {
            self.a.inspect_tx(tx_id).await
        } else if domain == self.b.domain() {
            self.b.inspect_tx(tx_id).await
        } else {
            Ok(None)
        }
    }
}
