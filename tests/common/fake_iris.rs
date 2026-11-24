//! Scripted fake Iris API, a fake transaction locator, and an Iris message
//! encoder for tests.
//!
//! `FakeIris` is cheap to clone; clones share one script and one call log, so
//! a test keeps a handle after it moves a clone into the `Resolver`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use bridge_watcher::domain::{BurnMessage, Bytes32, Domain};
use bridge_watcher::iris::{IrisApi, IrisError, IrisMessage, IrisQuery, IrisResponse};
use bridge_watcher::source::{SourceError, TxEvidence, TxInspector};

/// One scripted answer.
#[derive(Clone, Debug)]
pub enum Reply {
    /// HTTP 404.
    NotFound,
    /// HTTP 200 with a body.
    Response(IrisResponse),
    /// HTTP 429.
    RateLimited,
    /// Transport error or HTTP 5xx.
    Transient(String),
}

#[derive(Default)]
struct State {
    queued: HashMap<(Domain, IrisQuery), VecDeque<Reply>>,
    sticky: HashMap<(Domain, IrisQuery), Reply>,
    calls: Vec<(Domain, IrisQuery)>,
}

/// Fake Iris. A query without a script answers `NotFound`.
#[derive(Clone, Default)]
pub struct FakeIris {
    state: Arc<Mutex<State>>,
}

impl FakeIris {
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers once, in call order, before the sticky reply is used.
    pub fn push(&self, source: Domain, query: IrisQuery, reply: Reply) {
        let mut s = self.state.lock().unwrap();
        s.queued
            .entry((source, query))
            .or_default()
            .push_back(reply);
    }

    /// Answers every call that has no queued reply.
    pub fn set(&self, source: Domain, query: IrisQuery, reply: Reply) {
        self.state
            .lock()
            .unwrap()
            .sticky
            .insert((source, query), reply);
    }

    pub fn calls(&self) -> Vec<(Domain, IrisQuery)> {
        self.state.lock().unwrap().calls.clone()
    }

    pub fn call_count(&self) -> usize {
        self.state.lock().unwrap().calls.len()
    }
}

impl IrisApi for FakeIris {
    async fn get_messages(
        &self,
        source: Domain,
        query: IrisQuery,
    ) -> Result<Option<IrisResponse>, IrisError> {
        let mut s = self.state.lock().unwrap();
        let key = (source, query);
        s.calls.push(key.clone());
        let reply = s
            .queued
            .get_mut(&key)
            .and_then(VecDeque::pop_front)
            .or_else(|| s.sticky.get(&key).cloned())
            .unwrap_or(Reply::NotFound);
        match reply {
            Reply::NotFound => Ok(None),
            Reply::Response(r) => Ok(Some(r)),
            Reply::RateLimited => Err(IrisError::RateLimited),
            Reply::Transient(e) => Err(IrisError::Transient(e)),
        }
    }
}

/// Fake `TxInspector`: a table `(domain, tx) -> evidence`, a failure switch
/// and a call count.
#[derive(Clone, Default)]
pub struct FakeInspector {
    txs: Arc<Mutex<HashMap<(u32, String), TxEvidence>>>,
    calls: Arc<Mutex<usize>>,
    failing: Arc<Mutex<bool>>,
}

impl FakeInspector {
    pub fn new() -> Self {
        Self::default()
    }

    /// The chain of `domain` knows `tx` at `height` with these burns.
    pub fn insert(&self, domain: Domain, tx: &str, height: u64, burns: Vec<BurnMessage>) {
        self.txs
            .lock()
            .unwrap()
            .insert((domain.0, tx.to_string()), TxEvidence { height, burns });
    }

    /// Every call fails with an `Rpc` error while `on` is true.
    pub fn set_failing(&self, on: bool) {
        *self.failing.lock().unwrap() = on;
    }

    pub fn call_count(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl TxInspector for FakeInspector {
    async fn inspect_tx(
        &self,
        domain: Domain,
        tx_id: &str,
    ) -> Result<Option<TxEvidence>, SourceError> {
        *self.calls.lock().unwrap() += 1;
        if *self.failing.lock().unwrap() {
            return Err(SourceError::Rpc("injected inspect failure".into()));
        }
        Ok(self
            .txs
            .lock()
            .unwrap()
            .get(&(domain.0, tx_id.to_string()))
            .cloned())
    }
}

fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// Encodes a CCTP V2 burn message the way Iris returns it: the source-written
/// fields of `m` plus the Iris-filled ones.
pub fn encode_message(m: &BurnMessage, nonce: Bytes32, fte: u32, fee_executed: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&m.source_domain.0.to_be_bytes());
    out.extend_from_slice(&m.destination_domain.0.to_be_bytes());
    out.extend_from_slice(&nonce.0);
    out.extend_from_slice(&m.sender.0);
    out.extend_from_slice(&m.recipient.0);
    out.extend_from_slice(&m.destination_caller.0);
    out.extend_from_slice(&m.min_finality_threshold.to_be_bytes());
    out.extend_from_slice(&fte.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&m.burn_token.0);
    out.extend_from_slice(&m.mint_recipient.0);
    out.extend_from_slice(&word(m.amount));
    out.extend_from_slice(&m.depositor.0);
    out.extend_from_slice(&word(m.max_fee));
    out.extend_from_slice(&word(fee_executed));
    out.extend_from_slice(&word(0));
    out.extend_from_slice(&m.hook_data);
    out
}

/// A ready, complete Iris message for `m` with nonce `[nonce_byte; 32]`.
pub fn ready_message(m: &BurnMessage, nonce_byte: u8) -> IrisMessage {
    IrisMessage {
        message: Some(encode_message(m, Bytes32([nonce_byte; 32]), 2000, 0)),
        attestation_ready: true,
        status: "complete".to_string(),
        delay_reason: None,
        cctp_version: Some(2),
        destination_tx: None,
    }
}

/// Not ready: `message = "0x"`, attestation pending.
pub fn pending_message() -> IrisMessage {
    IrisMessage {
        message: None,
        attestation_ready: false,
        status: "pending_confirmations".to_string(),
        delay_reason: None,
        cctp_version: Some(2),
        destination_tx: None,
    }
}

/// A response with the given messages and source tx.
pub fn response(tx: &str, messages: Vec<IrisMessage>) -> IrisResponse {
    IrisResponse {
        source_tx: Some(tx.to_string()),
        messages,
    }
}
