//! Codec and matching tests, including the six real mainnet fixtures.

mod common;

use bridge_watcher::codec::{
    CodecError, DEPOSIT_FOR_BURN, DepositForBurnEvent, EVENT_IX_TAG, MESSAGE_RECEIVED,
    MessageReceivedEvent, ReceiveFields, decode_burn_body, decode_burn_message, decode_header,
    decode_receive, split_event_ix,
};
use bridge_watcher::domain::{BurnMessage, Bytes32, Domain, Mode};
use bridge_watcher::matching::{BurnSlot, IrisCandidate, assign_iris_messages, mode};
use common::fixtures::{self, InnerIx};
use sha2::{Digest, Sha256};

const TOKEN_MESSENGER_EVM: &str = "28b5a0e9c621a5badaa536219b3a228c8168cf5d";
const TOKEN_MESSENGER_MINTER: &str = "CCTPV2vPZJS2u2BBsUoscuikbYjnpFmbFsvVuJdgUMQe";
const MESSAGE_TRANSMITTER: &str = "CCTPV2Sm4AdWt5296sk4P66VBZ7bEhcARwFaaS9YPbeC";

fn evm_addr(hex_str: &str) -> Bytes32 {
    Bytes32::from_evm_address(hex::decode(hex_str).unwrap().try_into().unwrap())
}

fn nonce(hex_str: &str) -> Bytes32 {
    Bytes32(
        hex::decode(hex_str.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn tagged(tx: &serde_json::Value) -> Vec<InnerIx> {
    fixtures::inner_instructions(tx)
        .into_iter()
        .filter(|ix| split_event_ix(&ix.data).is_some())
        .collect()
}

#[test]
fn codec_fixture_log_deserializes_with_extra_fields() {
    let log = fixtures::base_burn_log();
    assert_eq!(log.block_number, Some(61_649_071));
    assert_eq!(log.log_index, Some(159));
    assert_eq!(log.block_timestamp, Some(1_795_520_189));
    assert!(!log.removed);
    let rx = fixtures::base_receive_log();
    assert_eq!(rx.log_index, Some(6));
}

#[test]
fn codec_decodes_base_message_sent_fixture() {
    let log = fixtures::base_burn_log();
    let bytes = fixtures::message_sent_bytes(&log);
    let header = decode_header(&bytes).unwrap();
    assert_eq!(header.version, 1);
    assert_eq!(header.source_domain, Domain(6));
    assert_eq!(header.destination_domain, Domain(5));
    assert_eq!(header.nonce, Bytes32::ZERO);
    assert_eq!(header.sender, evm_addr(TOKEN_MESSENGER_EVM));
    assert_eq!(header.recipient.to_base58(), TOKEN_MESSENGER_MINTER);
    assert_eq!(header.destination_caller, Bytes32::ZERO);
    assert_eq!(header.min_finality_threshold, 2000);
    assert_eq!(header.finality_threshold_executed, 0);

    let (burn, iris) = decode_burn_message(&bytes).unwrap();
    assert_eq!(burn.amount, 5_196_725_157);
    assert_eq!(
        burn.depositor,
        evm_addr("44b86c72cb96d9ff04e7b0b23124316bb884e35e")
    );
    assert_eq!(
        burn.burn_token,
        evm_addr("833589fcd6edb6e08f4c7c32d4f71b54bda02913")
    );
    assert_eq!(
        burn.mint_recipient.to_base58(),
        "8U3MV7x5CWc7p5sfL6kFQapcC56eGpjPgSMNTzJAFMw1"
    );
    assert_eq!(burn.max_fee, 0);
    assert!(burn.hook_data.is_empty());
    assert_eq!(iris.nonce, Bytes32::ZERO);
    assert_eq!(iris.fee_executed, 0);
    assert_eq!(iris.expiration_block, 0);
}

#[test]
fn codec_iris_message_equals_source_except_iris_fields() {
    let source = fixtures::message_sent_bytes(&fixtures::base_burn_log());
    let iris = fixtures::iris_message("iris_base_burn.json");
    assert_ne!(source, iris);
    let (s_burn, s_iris) = decode_burn_message(&source).unwrap();
    let (i_burn, i_iris) = decode_burn_message(&iris).unwrap();
    assert_eq!(s_burn, i_burn);
    assert_eq!(s_iris.nonce, Bytes32::ZERO);
    assert_eq!(
        i_iris.nonce,
        nonce("0xdc9db8e758a6080cd494d37c7df9f4b80f3745b1957223ec728bb6759287833f")
    );
    assert_eq!(i_iris.finality_threshold_executed, 2000);
}

#[test]
fn codec_rejects_short_header_and_body() {
    let msg = fixtures::iris_message("iris_base_burn.json");
    assert!(matches!(
        decode_header(&msg[..147]),
        Err(CodecError::TooShort {
            min: 148,
            len: 147,
            ..
        })
    ));
    assert!(matches!(
        decode_burn_body(&msg[148..148 + 227]),
        Err(CodecError::TooShort {
            min: 228,
            len: 227,
            ..
        })
    ));
    assert!(matches!(
        decode_burn_message(&msg[..148 + 100]),
        Err(CodecError::TooShort { .. })
    ));
}

#[test]
fn codec_rejects_unknown_versions() {
    let msg = fixtures::iris_message("iris_base_burn.json");
    let mut bad_header = msg.clone();
    bad_header[3] = 2;
    assert!(matches!(
        decode_header(&bad_header),
        Err(CodecError::BadVersion { found: 2, .. })
    ));
    let mut bad_body = msg.clone();
    bad_body[148 + 3] = 7;
    assert!(matches!(
        decode_burn_message(&bad_body),
        Err(CodecError::BadVersion { found: 7, .. })
    ));
}

#[test]
fn codec_rejects_amount_above_i64() {
    let msg = fixtures::iris_message("iris_base_burn.json");
    let amount_word = 148 + 68;
    // A bit above bit 63 of the low u64.
    let mut low = msg.clone();
    low[amount_word + 24] = 0x80;
    assert!(matches!(
        decode_burn_message(&low),
        Err(CodecError::Overflow { field: "amount" })
    ));
    // A bit in the upper 24 bytes of the u256.
    let mut high = msg.clone();
    high[amount_word] = 1;
    assert!(matches!(
        decode_burn_message(&high),
        Err(CodecError::Overflow { field: "amount" })
    ));
    // i64::MAX itself is accepted.
    let mut max = msg.clone();
    max[amount_word + 24..amount_word + 32].copy_from_slice(&i64::MAX.to_be_bytes());
    assert_eq!(decode_burn_message(&max).unwrap().0.amount, i64::MAX as u64);
    // The other u256 fields are checked too.
    let mut fee = msg.clone();
    fee[148 + 132 + 24] = 0x80;
    assert!(matches!(
        decode_burn_message(&fee),
        Err(CodecError::Overflow { field: "max_fee" })
    ));
}

#[test]
fn codec_discriminators_match_sha256() {
    let disc = |name: &str| -> [u8; 8] {
        let digest = Sha256::digest(format!("event:{name}").as_bytes());
        digest[..8].try_into().unwrap()
    };
    assert_eq!(DEPOSIT_FOR_BURN, disc("DepositForBurn"));
    assert_eq!(MESSAGE_RECEIVED, disc("MessageReceived"));
    // The tag is the Anchor event-CPI instruction prefix.
    assert_eq!(
        EVENT_IX_TAG,
        [0xe4, 0x45, 0xa5, 0x2e, 0x51, 0xcb, 0x9a, 0x1d]
    );
}

#[test]
fn codec_split_event_ix() {
    let mut data = EVENT_IX_TAG.to_vec();
    data.extend_from_slice(&DEPOSIT_FOR_BURN);
    data.extend_from_slice(&[1, 2, 3]);
    let (disc, payload) = split_event_ix(&data).unwrap();
    assert_eq!(disc, DEPOSIT_FOR_BURN);
    assert_eq!(payload, &[1, 2, 3]);
    assert!(split_event_ix(&data[..15]).is_none());
    assert!(split_event_ix(&[0u8; 20]).is_none());
}

#[test]
fn codec_solana_burn_fixture_event_equals_iris_message() {
    let tx = fixtures::json("solana_burn_to_base.tx.json");
    assert_eq!(tx["version"], 1);
    let events = tagged(&tx);
    // Two tagged instructions: the CCTP burn and the aggregator's own event.
    assert_eq!(events.iter().map(|e| e.index).collect::<Vec<_>>(), [9, 10]);

    let burn_ix = &events[0];
    let (disc, payload) = split_event_ix(&burn_ix.data).unwrap();
    assert_eq!(disc, DEPOSIT_FOR_BURN);
    let ev = DepositForBurnEvent::decode(payload).unwrap();
    let minter = Bytes32::from_base58(TOKEN_MESSENGER_MINTER).unwrap();
    let burn = ev.into_burn_message(Domain(5), minter).unwrap();
    assert_eq!(burn.destination_domain, Domain(6));
    assert_eq!(burn.amount, 21_000_000);
    assert_eq!(burn.max_fee, 2100);
    assert_eq!(burn.min_finality_threshold, 1000);
    assert_eq!(
        burn.depositor.to_base58(),
        "Bq3vfJV5KPerjc2eoa4PXQaJMvy6ACRQBRfwQ6wkanz7"
    );
    assert_eq!(burn.hook_data.len(), 32);

    let iris = fixtures::iris_message("iris_solana_burn.json");
    let (iris_burn, iris_fields) = decode_burn_message(&iris).unwrap();
    assert_eq!(burn, iris_burn);
    assert_eq!(
        iris_fields.nonce,
        nonce("0x980e3ffa5313ffad7c20f89ae813d278a96a1c825f6feabcc3bd2d8f75ff7406")
    );
    assert_eq!(iris_fields.fee_executed, 2100);
    assert_eq!(iris_fields.finality_threshold_executed, 1000);
}

#[test]
fn codec_solana_events_reject_trailing_and_truncated_payloads() {
    let tx = fixtures::json("solana_burn_to_base.tx.json");
    let burn_ix = &tagged(&tx)[0];
    let (_, payload) = split_event_ix(&burn_ix.data).unwrap();
    let mut trailing = payload.to_vec();
    trailing.push(0);
    assert!(matches!(
        DepositForBurnEvent::decode(&trailing),
        Err(CodecError::Borsh(_))
    ));
    assert!(matches!(
        DepositForBurnEvent::decode(&payload[..payload.len() - 1]),
        Err(CodecError::Borsh(_))
    ));
    assert!(matches!(
        MessageReceivedEvent::decode(&payload[..10]),
        Err(CodecError::Borsh(_))
    ));
}

#[test]
fn codec_decodes_evm_receive_fixture_equal_to_iris() {
    let log = fixtures::base_receive_log();
    let ev = fixtures::message_received(&log);
    assert_eq!(ev.sourceDomain, 5);
    assert_eq!(ev.finalityThresholdExecuted, 1000);
    let rx = decode_receive(ReceiveFields {
        source_domain: Domain(ev.sourceDomain),
        nonce: Bytes32(ev.nonce.0),
        sender: Bytes32(ev.sender.0),
        caller: Bytes32::from_evm_address(ev.caller.0.0),
        finality_threshold_executed: ev.finalityThresholdExecuted,
        message_body: &ev.messageBody,
    })
    .unwrap();
    assert_eq!(
        rx.nonce,
        nonce("0x980e3ffa5313ffad7c20f89ae813d278a96a1c825f6feabcc3bd2d8f75ff7406")
    );
    assert_eq!(rx.sender.to_base58(), TOKEN_MESSENGER_MINTER);
    assert_eq!(rx.body.amount, 21_000_000);
    assert_eq!(rx.body.fee_executed, 2100);
    assert_eq!(rx.body.max_fee, 2100);
    assert_eq!(rx.body.expiration_block, 62_078_381);
    assert_eq!(rx.body.hook_data.len(), 32);

    let iris = fixtures::iris_message("iris_solana_burn.json");
    assert_eq!(rx.body, decode_burn_body(&iris[148..]).unwrap());
}

#[test]
fn codec_bytes32_conversions() {
    let b = Bytes32::from_evm_address([0xab; 20]);
    assert_eq!(&b.0[..12], &[0u8; 12]);
    assert_eq!(&b.0[12..], &[0xab; 20]);
    assert_eq!(
        b.to_hex(),
        format!("0x{}{}", "0".repeat(24), "ab".repeat(20))
    );
    let k = Bytes32::from_base58(MESSAGE_TRANSMITTER).unwrap();
    assert_eq!(k.to_base58(), MESSAGE_TRANSMITTER);
    assert!(matches!(
        Bytes32::from_base58("0OIl"),
        Err(CodecError::BadBase58)
    ));
    assert!(matches!(
        Bytes32::from_base58("abc"),
        Err(CodecError::BadBase58)
    ));
}

fn burn(amount: u64) -> BurnMessage {
    common::burn_message(6, amount)
}

fn nonce_of(b: u8) -> Bytes32 {
    Bytes32([b; 32])
}

fn slot(id: i64, amount: u64, nonce: Option<u8>) -> BurnSlot {
    BurnSlot {
        id,
        message: burn(amount),
        nonce: nonce.map(nonce_of),
    }
}

fn cand(amount: u64, nonce: u8) -> Option<IrisCandidate> {
    Some(IrisCandidate {
        message: burn(amount),
        nonce: nonce_of(nonce),
    })
}

#[test]
fn matching_mode_threshold() {
    assert_eq!(mode(1000), Mode::Fast);
    assert_eq!(mode(500), Mode::Fast);
    assert_eq!(mode(1999), Mode::Fast);
    assert_eq!(mode(2000), Mode::Standard);
}

#[test]
fn matching_assign_by_fields() {
    let burns = vec![slot(10, 1, None), slot(11, 2, None), slot(12, 3, None)];
    let mut other_domain = cand(2, 40).unwrap();
    other_domain.message.destination_domain = Domain(99);
    // Different order, one extra message for another domain, one not usable.
    let iris = vec![
        Some(other_domain),
        cand(3, 31),
        None,
        cand(1, 11),
        cand(2, 21),
    ];
    let pairs = assign_iris_messages(&burns, &iris);
    assert_eq!(pairs, vec![(10, 3), (11, 4), (12, 1)]);
}

#[test]
fn matching_assign_identical_by_order() {
    let burns = vec![slot(1, 7, None), slot(2, 7, None)];
    let iris = vec![cand(7, 1), cand(7, 2)];
    assert_eq!(assign_iris_messages(&burns, &iris), vec![(1, 0), (2, 1)]);
    // One message for two identical burns: the second stays unmatched.
    assert_eq!(assign_iris_messages(&burns, &iris[..1]), vec![(1, 0)]);
}

#[test]
fn matching_unmatched_burn_stays_pending() {
    let burns = vec![slot(1, 7, None)];
    assert!(assign_iris_messages(&burns, &[cand(8, 1), None]).is_empty());
    assert!(assign_iris_messages(&burns, &[]).is_empty());
}

#[test]
fn matching_keeps_assigned_nonces_stable() {
    // Two identical burns A (id 1) and B (id 2).
    // Poll 1: message 0 not ready, message 1 ready: A gets message 1.
    let burns = vec![slot(1, 7, None), slot(2, 7, None)];
    let poll1 = vec![None, cand(7, 51)];
    assert_eq!(assign_iris_messages(&burns, &poll1), vec![(1, 1)]);

    // Poll 2: A now holds nonce 51. Both messages are ready.
    let burns = vec![slot(1, 7, Some(51)), slot(2, 7, None)];
    let poll2 = vec![cand(7, 50), cand(7, 51)];
    let mut pairs = assign_iris_messages(&burns, &poll2);
    pairs.sort();
    assert_eq!(pairs, vec![(1, 1), (2, 0)]);

    // Same result with the Iris order reversed.
    let reversed = vec![cand(7, 51), cand(7, 50)];
    let mut pairs = assign_iris_messages(&burns, &reversed);
    pairs.sort();
    assert_eq!(pairs, vec![(1, 0), (2, 1)]);
}

#[test]
fn matching_never_hands_out_held_nonce() {
    // A stale row (id 1) holds nonce 51. A new row (id 2, equal fields) exists.
    // Iris returns only nonce 51: the new row must get nothing.
    let burns = vec![slot(1, 7, Some(51)), slot(2, 7, None)];
    let iris = vec![cand(7, 51)];
    assert_eq!(assign_iris_messages(&burns, &iris), vec![(1, 0)]);

    // The stale row's own message is listed after another one.
    let iris = vec![cand(7, 52), cand(7, 51)];
    assert_eq!(assign_iris_messages(&burns, &iris), vec![(1, 1), (2, 0)]);
}

#[test]
fn matching_pinned_nonce_requires_equal_fields() {
    // Burn 1 holds nonce 51, but the message with nonce 51 has other fields.
    let burns = vec![slot(1, 7, Some(51)), slot(2, 8, None)];
    let iris = vec![cand(8, 51)];
    // Burn 1 is not paired, and nonce 51 is not given to burn 2 even though
    // burn 2 has equal fields.
    assert!(assign_iris_messages(&burns, &iris).is_empty());
}

#[test]
fn matching_guarantees_hold_on_all_small_inputs() {
    // Exhaustive check of G1-G3 over small combinations.
    let amounts = [1u64, 2];
    let nonces = [None, Some(1u8), Some(2)];
    for b0 in 0..6 {
        for b1 in 0..6 {
            for m0 in 0..6 {
                for m1 in 0..7 {
                    let burns = vec![
                        slot(1, amounts[b0 % 2], nonces[b0 / 2]),
                        slot(2, amounts[b1 % 2], nonces[b1 / 2]),
                    ];
                    // Held nonces are distinct (unique index).
                    if burns[0].nonce.is_some() && burns[0].nonce == burns[1].nonce {
                        continue;
                    }
                    let iris = vec![
                        cand(amounts[m0 % 2], 1 + (m0 / 2) as u8),
                        if m1 == 6 {
                            None
                        } else {
                            cand(amounts[m1 % 2], 1 + (m1 / 2) as u8)
                        },
                    ];
                    let pairs = assign_iris_messages(&burns, &iris);
                    let mut seen_b = vec![];
                    let mut seen_m = vec![];
                    for (id, j) in &pairs {
                        let b = burns.iter().find(|b| b.id == *id).unwrap();
                        let m = iris[*j].as_ref().unwrap();
                        assert_eq!(b.message, m.message, "G3");
                        if let Some(n) = b.nonce {
                            assert_eq!(n, m.nonce, "G1");
                        }
                        assert!(
                            burns
                                .iter()
                                .all(|o| o.id == b.id || o.nonce != Some(m.nonce)),
                            "G2"
                        );
                        assert!(!seen_b.contains(id) && !seen_m.contains(j));
                        seen_b.push(*id);
                        seen_m.push(*j);
                    }
                    // Liveness: a burn without a nonce stays unpaired only if
                    // every equal message is reserved by a held nonce, used,
                    // or carries a nonce that was already handed out.
                    let handed: Vec<_> = seen_m
                        .iter()
                        .map(|j| iris[*j].as_ref().unwrap().nonce)
                        .collect();
                    for b in burns.iter().filter(|b| b.nonce.is_none()) {
                        if seen_b.contains(&b.id) {
                            continue;
                        }
                        for (j, m) in iris.iter().enumerate() {
                            let Some(m) = m else { continue };
                            let free = !seen_m.contains(&j)
                                && burns.iter().all(|o| o.nonce != Some(m.nonce))
                                && !handed.contains(&m.nonce);
                            assert!(
                                !(free && m.message == b.message),
                                "liveness: burn {} left unpaired with free message {j}",
                                b.id
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn codec_rejects_fee_executed_and_expiration_above_i64() {
    let msg = fixtures::iris_message("iris_base_burn.json");
    for (offset, field) in [(164, "fee_executed"), (196, "expiration_block")] {
        let mut bad = msg.clone();
        bad[148 + offset + 24] = 0x80;
        assert!(matches!(
            decode_burn_message(&bad),
            Err(CodecError::Overflow { field: f }) if f == field
        ));
        let mut high = msg.clone();
        high[148 + offset + 5] = 1;
        assert!(matches!(
            decode_burn_body(&high[148..]),
            Err(CodecError::Overflow { field: f }) if f == field
        ));
    }
}

#[test]
fn codec_solana_burn_event_above_i64_is_overflow() {
    let tx = fixtures::json("solana_burn_to_base.tx.json");
    let (_, payload) = split_event_ix(&tagged(&tx)[0].data)
        .map(|(d, p)| (d, p.to_vec()))
        .unwrap();
    let minter = Bytes32::from_base58(TOKEN_MESSENGER_MINTER).unwrap();
    let ok = DepositForBurnEvent::decode(&payload).unwrap();

    let mut big_amount = ok.clone();
    big_amount.amount = i64::MAX as u64 + 1;
    assert!(matches!(
        big_amount.into_burn_message(Domain(5), minter),
        Err(CodecError::Overflow { field: "amount" })
    ));
    let mut big_fee = ok.clone();
    big_fee.max_fee = u64::MAX;
    assert!(matches!(
        big_fee.into_burn_message(Domain(5), minter),
        Err(CodecError::Overflow { field: "max_fee" })
    ));
    let mut max = ok;
    max.amount = i64::MAX as u64;
    assert_eq!(
        max.into_burn_message(Domain(5), minter).unwrap().amount,
        i64::MAX as u64
    );
}

#[test]
fn codec_message_received_event_rejects_trailing_bytes_and_short_body() {
    let tx = fixtures::json("solana_receive_from_base.tx.json");
    let received = tagged(&tx).into_iter().find(|e| e.index == 4).unwrap();
    let (_, payload) = split_event_ix(&received.data).unwrap();
    let mut trailing = payload.to_vec();
    trailing.push(0);
    assert!(matches!(
        MessageReceivedEvent::decode(&trailing),
        Err(CodecError::Borsh(_))
    ));
    assert!(matches!(
        MessageReceivedEvent::decode(&payload[..payload.len() - 1]),
        Err(CodecError::Borsh(_))
    ));
    // A well-formed event whose embedded body is too short.
    let mut ev = MessageReceivedEvent::decode(payload).unwrap();
    ev.message_body.truncate(100);
    assert!(matches!(
        ev.into_receive_message(),
        Err(CodecError::TooShort {
            min: 228,
            len: 100,
            ..
        })
    ));
}

#[test]
fn codec_decode_receive_rejects_short_body() {
    let fields = |body: &[u8]| {
        decode_receive(ReceiveFields {
            source_domain: Domain(5),
            nonce: Bytes32::ZERO,
            sender: Bytes32::ZERO,
            caller: Bytes32::ZERO,
            finality_threshold_executed: 1000,
            message_body: body,
        })
    };
    assert!(matches!(
        fields(&[0u8; 227]),
        Err(CodecError::TooShort {
            min: 228,
            len: 227,
            ..
        })
    ));
    assert!(matches!(
        fields(&[0u8; 228]),
        Err(CodecError::BadVersion { found: 0, .. })
    ));
}
