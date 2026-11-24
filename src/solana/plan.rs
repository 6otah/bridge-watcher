//! Batch planning for Solana scans (pure).
//!
//! A scan fetches one transaction per listed signature, which is expensive, so
//! it works on a budget. The budget is soft: a batch always ends at a slot
//! boundary, because the cursor is a slot and a commit must never split one
//! (ADR 0002).

/// One entry of a signature listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureInfo {
    /// Base58 first signature of the transaction.
    pub signature: String,
    /// Slot that holds the transaction.
    pub slot: u64,
    /// The transaction failed (`err != null`). It cannot carry a trusted event
    /// and is never fetched.
    pub failed: bool,
}

/// The part of a listing that one scan processes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    /// Signatures to process, in ascending slot order, whole slots only.
    pub take: Vec<SignatureInfo>,
    /// Every transaction of the listing at or below this slot is in `take`.
    pub complete_through: u64,
}

/// Chooses the longest prefix of whole slots whose number of non-failed
/// signatures is at most `budget`. The first slot is always taken, even if it
/// alone exceeds the budget, so every scan makes progress.
///
/// `sigs` are the signatures of `(after, up_to]` in ascending slot order.
/// `complete_through` is `up_to` when everything is taken; otherwise it is the
/// slot before the first slot left out. That is a valid claim because the
/// listing holds every relevant transaction of the range (scan contract S2),
/// so the slots in between hold none.
pub fn plan_batch(sigs: &[SignatureInfo], up_to: u64, budget: usize) -> Batch {
    let mut end = 0;
    let mut cost = 0;
    while end < sigs.len() {
        let slot = sigs[end].slot;
        let group = sigs[end..].iter().take_while(|s| s.slot == slot);
        let (len, group_cost) = group.fold((0, 0), |(n, c), s| (n + 1, c + usize::from(!s.failed)));
        if end > 0 && cost + group_cost > budget {
            break;
        }
        cost += group_cost;
        end += len;
    }
    Batch {
        take: sigs[..end].to_vec(),
        complete_through: sigs.get(end).map_or(up_to, |s| s.slot.saturating_sub(1)),
    }
}
