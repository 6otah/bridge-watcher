# bridge-watcher

A read-only watcher for [Circle CCTP V2](https://developers.circle.com/cctp)
USDC transfers between **Solana** (domain 5) and **Base** (domain 6).

It reads both chains, stores every burn and every receive in SQLite, joins them
into transfers, handles finality and reorgs, and raises alerts when a transfer
looks late, stuck or wrong. It holds no keys, signs nothing and never moves
funds: it only calls read RPC methods and the public Circle attestation API
(Iris), and optionally sends Telegram messages.

This is Stage 1 of a larger project. The full design is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Architecture

Five tasks share one SQLite database. They do not share memory and do not send
each other messages: the database is the only integration point, so each task
can restart and be tested alone.

```
 Base RPC ────> Ingestor<EvmSource> ─────┐
                                         ├──> SQLite <── Monitor
 Solana RPC ──> Ingestor<SolanaSource> ──┘      ^  │         │
                                                │  │         v
 Circle Iris ─────────> Resolver ───────────────┘  └──> Notifier ──> log / Telegram
   (nonces, attestations)
```

The resolver also reads both chains to verify receives that have no burn (see
"Orphan receives" below).

| Task | What it does |
|---|---|
| Ingestors (2) | Read burns and receives from one chain. Track finality. Roll back unfinalized rows that a reorg removed. |
| Resolver | Polls Iris for the nonce and attestation of each burn. Verifies receives that have no burn against the source chain. |
| Monitor | Evaluates the alert rules over the database and syncs the `alerts` table. |
| Notifier | Delivers new alerts to Telegram (if configured) or only logs them. |

What counts as an event:

- Base burn: the `MessageSent` log of MessageTransmitterV2, sent by
  TokenMessengerV2 towards Solana (ADR 0006). Base receive: the
  `MessageReceived` log from Solana's token messenger.
- Solana burn: the `DepositForBurn` event; Solana receive: the
  `MessageReceived` event. Both are read from inner instructions of CCTP
  programs. An event counts only if the transaction succeeded, the instruction
  is an inner instruction, and its program id (resolved through address lookup
  tables) is the CCTP program. Other programs emit events with the same tag and
  are ignored.

Not in scope: other CCTP domains, CCTP V1, relaying or claiming, light-client
verification, a web UI.

## Finality and reorgs

Each chain has a **cursor**: every relevant event at or below it is stored as
final. Above the cursor is the **tail**: the heights up to the chain head that
are not final yet.

On every tick, for each chain, the ingestor:

1. reads the finalized height `F` and the head height;
2. **finalizes**: scans `(cursor, F]` at finalized commitment, stores the events
   as final, and moves the cursor;
3. only when the cursor has reached `F`, **re-derives the tail**: scans
   `(F, head]` again (capped by `tail_max`), stores the events as unfinalized,
   and deletes unfinalized rows that the new scan no longer returns.

There is no reorg detector. A reorg shows up as a different scan result for the
same range, and the rows that are gone are deleted (and logged in the
`rollbacks` table). Rules the store enforces:

- **Final rows never change.** The only `DELETE` removes unfinalized rows, and
  SQL triggers abort any attempt to delete or edit a final row. They also
  stop `INSERT OR REPLACE`, but only on the store's own connections, because
  `recursive_triggers` is a per-connection setting and the store sets it on
  every connection it opens. Another tool that opens the file directly is not
  covered.
- **The cursor moves with its rows.** A scan's rows, its deletions and the
  cursor update are one SQLite transaction, and the cursor moves only if it
  still has the value the scan started from (compare-and-swap). If two
  processes ran on one database, only competing final scans would fail fast
  (`CursorMoved`); their tail scans, resolvers and monitors are not guarded.
  Run one instance per database.
- **A crash at any point is safe.** After a restart the next scan starts from
  the stored cursor. Events are keyed by `(domain, tx, index)`, so a replay
  updates rows and never duplicates them. A test fails the ingestor before each
  commit and checks that the final database equals a run without a failure.

On Solana the cursor is a slot, and a scan always ends at a slot boundary.
Final scans ask the node to prove it has reached the target slot
(`minContextSlot`) and fetch each transaction at `finalized` commitment.
See ADR 0001 and ADR 0002.

## Why matching needs Iris

A burn and its receive are joined by `(source domain, nonce)`. But the nonce is
**assigned off-chain by Circle**: the source chain writes a zero nonce, and Iris
fills it in when it attests the message. So a burn gets its nonce only after the
resolver asks Iris, which matches the Iris message to the stored burn by every
source-written field (ADR 0007). The nonce is write-once. The join of burn and
receive is a SQL view, not stored state, so a rollback on either side un-matches
automatically (ADR 0008).

### Orphan receives

A final receive with no burn is an orphan. For each one the resolver uses Iris
only to find the source transaction. It then reads the source chain itself and
checks that the transaction contains a burn equal to the attested message (ADR
0012). No equal burn means value was minted without a matching on-chain burn
(`iris_mismatch`); an equal burn that we already hold, final, under another
nonce means the same burn was attested and minted twice (`double_mint`); a
transaction the chain cannot show, or a nonce Iris does not know, becomes
`mint_without_burn` after a few lookups; a burn from before the
start height is ignored; a burn inside a range we scanned but did not store is
`ingestion_gap`. Lookups are bounded (see Known limitations).

## Alerts

The monitor evaluates these rules every 30 s by default. Absence is claimed only
after the relevant data was read after the deadline.

| Alert | Severity | Meaning |
|---|---|---|
| `attestation_delayed` | warning | Iris has not attested a burn within the SLA for its chain and mode |
| `unclaimed` | warning | Attested, no receive yet, the destination chain was scanned after the deadline, and the burn lies inside the destination window (not `pre_window`) |
| `mint_without_burn` | critical | A final receive with no burn: Iris does not know the nonce, or the source transaction is not on the source chain, after `monitor.mint_without_burn_lookups` lookups |
| `iris_mismatch` | critical | A final receive whose attested message equals no burn of its source transaction on the source chain (value moved without an equal on-chain burn) |
| `double_mint` | critical | A final receive whose content equals an on-chain burn that is already attested under another nonce (the same burn was minted twice) |
| `ingestion_gap` | warning | A receive whose burn lies in a range we scanned but did not store |
| `orphan_unresolved` | warning | A receive without a burn that stayed undecidable after all `iris.orphan_max_lookups` lookups |
| `field_mismatch` | critical | A matched burn and receive disagree on a field (amount, recipient, token, fee, ...) |
| `duplicate_receive` | critical | More than one final receive for one nonce |
| `latency_outlier` | info | A transfer much slower than recent ones in its direction and mode |
| `component_stalled` | warning | A task has not succeeded for `stall_after_secs` |
| `ingestion_lagging` | warning | A chain's tail scan has not reached its target for `stall_after_secs` (measured from the last caught-up time, or from the start of the run). It does not check whether the ingestor is succeeding. |
| `finality_stalled` | warning | A chain's head is too far ahead of its finalized height |
| `reorg_rollback` | info | An unfinalized row was rolled back in the last 24 h |
| `monitor_truncated` | warning | A monitor candidate list reached `monitor.snapshot_limit`; alerts of the kinds it feeds are not resolved until it shrinks |

Alerts are stored once per `(kind, subject)` and de-duplicated across restarts.
The notifier sends alerts at or above `min_severity` (default `warning`) to
Telegram when `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are both set. Lower
ones, and all of them when Telegram is off, are only logged.

## Build and run

You need a Rust toolchain that satisfies `rust-version = "1.98"` in
`Cargo.toml`.

```
cargo build --release
```

1. **Config.** Copy `config/bridge-watcher.example.toml` to
   `bridge-watcher.toml` and adjust it, or pass `--config <path>` (or set
   `BW_CONFIG`). The file has the sections `[database]`, `[evm]`, `[solana]`,
   `[iris]`, `[monitor]` and `[alerts]`; every field has a default. The example
   holds the mainnet contract addresses and public RPC endpoints, and lists all
   values with comments (including `iris.orphan_batch`, `iris.orphan_retry_secs`
   and `monitor.snapshot_limit`). Secrets never go in the TOML file: every
   section rejects unknown keys, so a secret placed there fails to load.
2. **Environment.** Copy `.env.example` to `.env` (it is loaded if present and
   is ignored by git). All variables are optional:

   | Variable | Use |
   |---|---|
   | `BW_CONFIG` | Config file path |
   | `BW_EVM_RPC_URL`, `BW_SOLANA_RPC_URL` | Override the RPC URLs; use these for URLs that carry an API key. They must be http(s) URLs. |
   | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Set both for Telegram alerts, or neither (only one set is a configuration error) |
   | `RUST_LOG` | Log filter, default `info` |

   RPC URLs are treated as secrets: they are not logged and are removed from
   error messages.
3. **Commands.**

   ```
   bridge-watcher run                  # start all tasks; Ctrl-C stops them
   bridge-watcher status               # cursors, task health, transfer counts, open alerts
   bridge-watcher transfers [--state burned|attested|pre_window|completed] [--limit 50]
   ```

   `status` and `transfers` open the database read-only and work while `run` is
   active. Exit codes: 0 clean, 1 fatal error, 2 configuration error. If the
   database file does not exist yet, they say so and exit 0. `run` creates the
   database's parent directory.

   Example `status` on a database that `run` has not filled yet:

   ```
   bridge-watcher status at 2027-01-15 08:00:00 UTC

   Chains
     none yet (start `bridge-watcher run` first)

   Transfers    burned 0   attested 0   pre_window 0   completed 0
   Open alerts  critical 0   warning 0   info 0
   ```

   A transfer is `burned` (not attested yet), `attested` (attested, no receive
   yet), `completed`, or `pre_window`. `pre_window` is an attested burn whose
   receive may have happened before the destination chain's observation window
   began, so its absence cannot be seen (ADR 0013, see below). List them with
   `transfers --state pre_window`.

   Example `transfers` output. The values come from the mainnet captures in
   `tests/fixtures`; the second row is shown as `attested` for illustration:

   ```
   STATE      DIRECTION     MODE      USDC         BURN TX             RECEIVE TX          NONCE         LATENCY
   completed  base->solana  standard  5196.725157  0x90d79ce6..6bab9d  5SZfhkPdCW..h6iRVX  0xdc9db8e7..  1249s
   attested   solana->base  fast      21.000000    5hZceQXeq8..HdXWB2  -                   0x980e3ffa..  -
   ```

**Where it starts.** On the first run each chain starts at its current finalized
height and ingests forward: there is no backfill. To backfill, set
`start_height` (a block on Base, a slot on Solana) under `[evm]` or `[solana]`
before the first run. After the first run the stored value wins and a different
config value is ignored with a warning. Keep Solana backfills short: a scan
lists signatures from the chain tip down to its cursor, so a long backlog
catches up slowly. A receive whose burn is from before the start height is
classified `pre_start` and does not alert.

**Observation windows.** Each chain is observed from its own start. At the first
run the store records the chain time of that start (`chain_state.start_time`).
Base finality lags about 18 minutes, so the Base window starts that far in the
past, while the Solana window starts almost now. A Base to Solana Fast burn
from that gap was usually minted on Solana within seconds, before the Solana
window began, so its receive is not in the database. The monitor therefore
claims a missing receive (`unclaimed`) only for burns at least 60 s inside the
destination window; older ones are shown as `pre_window`. If their receive
appears later inside the window they become `completed` as usual.

Run one `run` process per database.

## Testing

All tests run offline: `cargo test --all-targets`. Network clients are replaced
by fakes that implement the same traits.

- Unit and store tests: codecs, matching (including an exhaustive check over
  small inputs), the SQLite invariants, the config rules.
- Ingestion tests with a scripted fake chain: reorg rollback, re-inclusion,
  partial scans, failure at every commit point and restart.
- Golden tests (`tests/golden.rs`): real mainnet captures in `tests/fixtures/`
  (a Base burn, a Solana burn, the matching receives, and the Iris answers) go
  through the real decoders, ingestors, resolver, monitor and store. Both
  directions end as one completed transfer with the expected latency (1249 s
  Standard, 5 s Fast). A one-unit amount change raises `field_mismatch`, a
  tampered Iris message that is minted raises `iris_mismatch`, and orphan
  receives are classified `pre_start` or `missed`.
- CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`, `cargo clippy -D
  warnings`, `cargo test` and `cargo doc` with warnings denied.

The mainnet smoke run is manual. The tests do not prove behaviour against live
RPC providers.

## Smoke run results

Two short runs on 2026-11-24, both against the public RPC endpoints and
read-only. They are two short runs, not a long-term soak test.

### Run 1

25 minutes, with about 1 h of Base backfill and about 32 min of Solana backfill
(9000 slots at about 0.215 s per slot).

- 50 transfers seen; 37 matched end to end: 12 Base to Solana (9 Fast, 3
  Standard) and 25 Solana to Base.
- Latency: Fast 5 to 53 s; Base to Solana Standard about 1333 s.
- 0 errors, 0 rollbacks, 0 alerts, and no unredacted RPC URL in the logs.
- One transient publicnode error, `-32602 "block range extends beyond current
  head block"`, was retried on the next tick. This confirmed the unverified
  fact U9.
- 34 Solana `getTransaction` HTTP 429 answers in the first 5 minutes of the
  backfill, all retried; Solana caught up in under 5 minutes.
- The run found the pre-window gap: 11 Base to Solana Fast burns had been
  minted on Solana before the Solana window began, which would have raised
  false `unclaimed` alerts. This led to ADR 0013 and the `pre_window` state.

### Run 2

20 minutes on a fresh database, with about 1 h of Base backfill (18000 blocks)
and about 1 h of Solana backfill (16700 slots). `unclaimed_after_secs` was
lowered to 300 to exercise the coverage rule.

- 64 transfers: 57 completed, 6 `pre_window` (Base to Solana burns minted on
  Solana before the Solana window began), 1 burned (waiting for attestation),
  and 0 `attested`.
- No false `unclaimed` alert. This is the fix for the run 1 finding (ADR 0013).
- 0 errors, 0 rollbacks, 0 critical alerts, and no unredacted RPC URL in the
  logs.
- Two warning alerts, `component_stalled` and `ingestion_lagging` for Solana,
  fired 330 s after the start and resolved by themselves about 4 minutes later.
  The cause was the 1-hour Solana backfill on the public RPC (50
  `getTransaction` HTTP 429 retries), which took about 8 minutes. Health is
  recorded per tick, so one long catch-up tick looks like a stall.
- Base: 6 transient `-32602 "block range extends beyond current head block"`
  answers from the load-balanced public RPC, each retried on the next tick.
  This confirmed U9 again.

## Known limitations

- **Public RPC (risk R1).** The default config uses public, load-balanced RPC
  endpoints. A backend that is behind can return a short `eth_getLogs` result
  for a finalized range, and an event in it would then be missed. A missed burn
  makes its receive an orphan, which raises `ingestion_gap`. A missed receive
  makes its burn `unclaimed`. Set `BW_EVM_RPC_URL` to a dedicated endpoint to
  reduce the risk. Solana is guarded by `minContextSlot` and by fetching
  transactions at `finalized`.
- **Backfill warnings.** During a long backfill on a rate-limited RPC, a single
  catch-up tick can take minutes, so `component_stalled` and `ingestion_lagging`
  warnings can fire until the chain catches up. They resolve automatically. Use
  a dedicated RPC or a shorter backfill.
- **Re-attestation of an expired Fast message (Q1, R9, U10).** If Circle
  re-attests an expired Fast message under a new nonce (it is unverified
  whether the nonce changes), the stored burn still holds the old nonce. A mint
  under the new nonce would then raise a false critical `double_mint`.
- **Pre-window burns are not claimed (risk R13).** A burn older than the
  destination window start (plus 60 s) that really was never claimed gets no
  `unclaimed` alert, because its receive could have happened before we were
  watching. This is bounded: mostly the roughly 18 minutes before the first
  start on Base to Solana. List such burns with
  `transfers --state pre_window` and check them by hand.
- **Orphan receives are verified, with bounded work.** A final receive with no
  burn is checked against the source chain: Iris names the source transaction,
  and the chain itself must hold a burn equal to the attested message (ADR
  0012). No equal burn is a critical `iris_mismatch`; an unknown nonce or
  source transaction becomes a critical `mint_without_burn` after
  `monitor.mint_without_burn_lookups` (default 3) lookups. A receive whose
  content equals a burn that is already final and attested under another nonce
  is a critical `double_mint`. Each orphan gets a strict maximum of
  `iris.orphan_max_lookups` (default 6) attempts, failed ones included, spaced
  `iris.orphan_retry_secs` (default 600 s), at most `iris.orphan_batch` orphans
  per tick. A failed attempt keeps the stored verdict; if the last attempt
  fails with no verdict, or the orphan stays undecidable, it ends as
  `orphan_unresolved` (warning), so nothing is retried forever. Only an Iris
  HTTP 429 is not an attempt: it pauses all Iris calls.
- **Double mint of an old burn (ADR 0012).** A double mint of a burn below
  `start_height` is not detectable: we do not store such burns, so we do not
  know their nonces.
- **Database schema version 2.** The database file has schema version 2. A
  file from an older build (version 1) is rejected with a clear error; delete
  it and start again. There is no migration. Before a mint, a burn whose Iris
  message differs from the burn only raises the `attestation_delayed` warning,
  because no value moved yet.
- **Old source transactions (risk R11).** A public RPC with short history can
  fail to serve an old but real source transaction. Its receive then looks like
  `source_not_found` and can raise a false critical `mint_without_burn`. Use a
  full-history RPC for production. How far back the public endpoints serve is
  unverified (U14).
- **Monitor lists are capped.** Each candidate list is limited to
  `monitor.snapshot_limit` rows (default 1000), newest first. When one is cut,
  its alert kinds are never resolved and `monitor_truncated` reports it.
- **Trust.** RPC data is trusted. Iris, the destination receive and the
  re-read of the source transaction act as independent cross-checks
  (`field_mismatch`, `mint_without_burn`, `iris_mismatch`).
- **Scope.** Stage 1 covers only the Base and Solana pair, CCTP V2 and the
  mainnet configuration (testnet addresses are not verified). There is no
  `rescan` repair command, no web UI, no Postgres, and no support for more than
  one process per database.
- **Undecodable events stop ingestion.** A CCTP event that passes the identity
  filter but does not decode halts that chain's ingestion at that range, by
  design. The tick fails and retries with backoff, and `component_stalled`
  reports it.
- Some protocol facts the design relies on (for example how a lagging Solana
  node answers `minContextSlot`) are listed as unverified in section 18.2 of the
  architecture document until a live run confirms them.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): the design, invariants, test plan
  and unverified facts.
- Decision records:
  [0001 reorgs: re-derive the tail](docs/adr/0001-reorg-rederive-unfinalized-tail.md),
  [0002 Solana slot cursor](docs/adr/0002-solana-slot-cursor.md),
  [0003 SQLite](docs/adr/0003-sqlite-storage.md),
  [0004 SQLite from async code](docs/adr/0004-sqlite-access-from-async.md),
  [0005 Solana raw JSON-RPC](docs/adr/0005-solana-raw-json-rpc.md),
  [0006 EVM burn record](docs/adr/0006-evm-burn-record-message-sent.md),
  [0007 Iris mapping by fields](docs/adr/0007-iris-mapping-by-message-fields.md),
  [0008 matching as a SQL view](docs/adr/0008-matching-as-sql-view.md),
  [0009 alerts outbox](docs/adr/0009-alerts-outbox-dedup.md),
  [0010 error policy](docs/adr/0010-error-policy-crash-only.md),
  [0011 single crate](docs/adr/0011-single-crate.md),
  [0012 orphan receive verification](docs/adr/0012-orphan-receive-verification.md),
  [0013 destination coverage window](docs/adr/0013-destination-coverage-window.md).

## License

MIT, see [LICENSE](LICENSE).
