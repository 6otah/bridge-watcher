//! Matching hardening against malformed Iris responses (review carry-over N1).

mod common;

use bridge_watcher::domain::Bytes32;
use bridge_watcher::matching::{BurnSlot, IrisCandidate, assign_iris_messages};
use common::burn_message;

fn slot(id: i64, amount: u64, nonce: Option<u8>) -> BurnSlot {
    BurnSlot {
        id,
        message: burn_message(6, amount),
        nonce: nonce.map(|n| Bytes32([n; 32])),
    }
}

fn cand(amount: u64, nonce: u8) -> Option<IrisCandidate> {
    Some(IrisCandidate {
        message: burn_message(6, amount),
        nonce: Bytes32([nonce; 32]),
    })
}

#[test]
fn matching_duplicate_nonce_messages_go_to_one_identical_burn() {
    let burns = [slot(1, 10, None), slot(2, 10, None)];
    let iris = [cand(10, 7), cand(10, 7)];
    let pairs = assign_iris_messages(&burns, &iris);
    assert_eq!(pairs, vec![(1, 0)], "one nonce must reach one burn only");
}

#[test]
fn matching_duplicate_nonce_messages_go_to_one_burn_of_different_content() {
    // A malformed response: two messages with different content, same nonce.
    let burns = [slot(1, 10, None), slot(2, 20, None)];
    let iris = [cand(10, 7), cand(20, 7)];
    let pairs = assign_iris_messages(&burns, &iris);
    assert_eq!(pairs, vec![(1, 0)]);
}

#[test]
fn matching_duplicate_nonce_does_not_disturb_other_nonces() {
    let burns = [slot(1, 10, None), slot(2, 10, None), slot(3, 10, None)];
    let iris = [cand(10, 7), cand(10, 7), cand(10, 8)];
    let pairs = assign_iris_messages(&burns, &iris);
    assert_eq!(pairs, vec![(1, 0), (2, 2)]);
    let nonces: Vec<_> = pairs
        .iter()
        .map(|(_, j)| iris[*j].as_ref().unwrap().nonce)
        .collect();
    assert_ne!(nonces[0], nonces[1]);
}

#[test]
fn matching_pinned_burn_blocks_duplicate_of_its_nonce() {
    let burns = [slot(1, 10, Some(7)), slot(2, 10, None)];
    let iris = [cand(10, 7), cand(10, 7)];
    let pairs = assign_iris_messages(&burns, &iris);
    assert_eq!(pairs, vec![(1, 0)], "the held nonce stays with its burn");
}

#[test]
fn matching_every_nonce_is_used_at_most_once_under_any_order() {
    let nonces = [7u8, 7, 8, 7, 8];
    let burns: Vec<_> = (1..=5).map(|id| slot(id, 10, None)).collect();
    let iris: Vec<_> = nonces.iter().map(|n| cand(10, *n)).collect();
    let pairs = assign_iris_messages(&burns, &iris);
    let mut used: Vec<_> = pairs
        .iter()
        .map(|(_, j)| iris[*j].as_ref().unwrap().nonce)
        .collect();
    used.sort_by_key(|n| n.0);
    used.dedup();
    assert_eq!(used.len(), pairs.len());
    assert_eq!(pairs.len(), 2);
}
