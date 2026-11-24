//! bridge-watcher: a read-only watcher for Circle CCTP V2 USDC transfers
//! between Solana (domain 5) and Base (domain 6).
//!
//! The design is in `docs/ARCHITECTURE.md`. Modules are layered: `domain`,
//! `codec`, `matching`, `ratelimit` and `config` are pure; `source`, `evm`,
//! `solana` and `iris` talk to the network; `store` owns all SQL; `ingest`,
//! `resolver`, `monitor` and `notify` are the background tasks that `app`
//! wires together.

#![forbid(unsafe_code)]

pub mod app;
pub mod cli;
pub mod codec;
pub mod config;
pub mod domain;
pub mod evm;
pub mod ingest;
pub mod iris;
pub mod matching;
pub mod monitor;
pub mod notify;
pub mod ratelimit;
pub mod resolver;
pub mod solana;
pub mod source;
pub mod store;
