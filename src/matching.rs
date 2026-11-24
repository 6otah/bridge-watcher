//! Matching of Iris messages to burns, and mode classification. Pure.
//!
//! Invariants: a burn gets at most one Iris message, and a message goes to at
//! most one burn. Messages match only when all source-written fields are equal,
//! and an assigned nonce never moves to another burn (ADR 0007).

use crate::domain::{BurnMessage, Bytes32, Mode};

/// Finality threshold of a Standard (finalized) transfer.
const STANDARD_THRESHOLD: u32 = 2000;

/// Fast if the burn asked for less than finalized (2000), else Standard.
pub fn mode(min_finality_threshold: u32) -> Mode {
    if min_finality_threshold < STANDARD_THRESHOLD {
        Mode::Fast
    } else {
        Mode::Standard
    }
}

/// One stored burn of the source transaction.
#[derive(Clone, Debug)]
pub struct BurnSlot {
    /// Row id of the burn.
    pub id: i64,
    /// Source-written content of the burn.
    pub message: BurnMessage,
    /// Nonce already stored for the burn, if any.
    pub nonce: Option<Bytes32>,
}

/// One usable Iris message: ready, decodable, CCTP V2, non-zero nonce.
#[derive(Clone, Debug)]
pub struct IrisCandidate {
    /// Source-written part of the decoded message.
    pub message: BurnMessage,
    /// Nonce Iris assigned.
    pub nonce: Bytes32,
}

/// Assigns Iris messages of one source transaction to the burns of that
/// transaction.
///
/// `burns` holds ALL stored burns of the transaction (any status), sorted by
/// `event_index`. `iris[j]` is `Some` for a usable message `j`, `None`
/// otherwise. Returns `(burn_id, j)` pairs; each burn and each message is used
/// at most once.
///
/// Guarantees:
/// - G1: a burn that holds a nonce is paired only with the message that has
///   that nonce.
/// - G2: a nonce held by any burn of the transaction is never paired with
///   another burn.
/// - G3: every pair has an equal [`BurnMessage`].
///
/// Steps: reserve every message whose nonce a burn holds; pin each holding burn
/// to its message if the fields are equal; give the remaining messages
/// greedily, in `event_index` order, to burns without a nonce. Greedy is
/// correct because equal burns are interchangeable for the first assignment.
///
/// A malformed Iris response can hold two messages with one nonce. Every nonce
/// that gets paired is marked used, so the second message is never handed to
/// another burn and the store never sees the same nonce twice.
pub fn assign_iris_messages(
    burns: &[BurnSlot],
    iris: &[Option<IrisCandidate>],
) -> Vec<(i64, usize)> {
    let held = |c: &IrisCandidate| burns.iter().any(|b| b.nonce == Some(c.nonce));
    let reserved: Vec<bool> = iris.iter().map(|m| m.as_ref().is_some_and(held)).collect();
    let mut used = vec![false; iris.len()];
    let mut used_nonces: Vec<Bytes32> = Vec::new();
    let mut paired = vec![false; burns.len()];
    let mut pairs = Vec::new();

    for (bi, burn) in burns.iter().enumerate() {
        let Some(nonce) = burn.nonce else { continue };
        paired[bi] = true;
        let hit = iris.iter().enumerate().find(|(j, m)| {
            !used[*j]
                && m.as_ref()
                    .is_some_and(|m| m.nonce == nonce && m.message == burn.message)
        });
        if let Some((j, _)) = hit {
            used[j] = true;
            used_nonces.push(nonce);
            pairs.push((burn.id, j));
        }
    }
    for (bi, burn) in burns.iter().enumerate() {
        if paired[bi] {
            continue;
        }
        let hit = iris.iter().enumerate().find(|(j, m)| {
            !reserved[*j]
                && !used[*j]
                && m.as_ref()
                    .is_some_and(|m| m.message == burn.message && !used_nonces.contains(&m.nonce))
        });
        if let Some((j, m)) = hit {
            used[j] = true;
            if let Some(m) = m {
                used_nonces.push(m.nonce);
            }
            pairs.push((burn.id, j));
        }
    }
    pairs
}
