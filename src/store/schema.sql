-- One row per watched chain. Owner: ingest.
CREATE TABLE chain_state (
    domain              INTEGER PRIMARY KEY,          -- CCTP domain id
    name                TEXT    NOT NULL,             -- config name, e.g. 'base'
    start_height        INTEGER NOT NULL,             -- first height in scope; never changes
    start_time          INTEGER NOT NULL,             -- chain time of the last block <= start_height - 1; never changes (ADR 0013)
    final_height        INTEGER NOT NULL,             -- the cursor (I1, I2)
    observed_finalized  INTEGER,                      -- last finalized height read from RPC
    observed_head       INTEGER,                      -- last head height read from RPC
    scanned_head        INTEGER,                      -- top of the last complete tail scan
    caught_up_at        INTEGER,                      -- when a tail scan last reached its target
    updated_at          INTEGER NOT NULL,
    CHECK (final_height >= start_height - 1)
);

-- One row per background loop. Each loop writes only its own row.
CREATE TABLE health (
    component            TEXT PRIMARY KEY,            -- 'ingest:base', 'ingest:solana', 'resolver', 'notifier'
    started_at           INTEGER NOT NULL,
    last_ok_at           INTEGER,
    last_error           TEXT,                        -- already redacted
    last_error_at        INTEGER,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE burns (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,  -- ids are never reused
    -- identity and location (owner: ingest)
    source_domain           INTEGER NOT NULL,
    tx_id                   TEXT    NOT NULL,
    event_index             INTEGER NOT NULL,
    height                  INTEGER NOT NULL,
    block_hash              TEXT,
    block_time              INTEGER NOT NULL,
    finalized               INTEGER NOT NULL CHECK (finalized IN (0, 1)),
    -- source-written message fields (owner: ingest)
    destination_domain      INTEGER NOT NULL,
    sender                  BLOB    NOT NULL CHECK (length(sender) = 32),
    recipient               BLOB    NOT NULL CHECK (length(recipient) = 32),
    destination_caller      BLOB    NOT NULL CHECK (length(destination_caller) = 32),
    min_finality_threshold  INTEGER NOT NULL,
    burn_token              BLOB    NOT NULL CHECK (length(burn_token) = 32),
    mint_recipient          BLOB    NOT NULL CHECK (length(mint_recipient) = 32),
    amount                  INTEGER NOT NULL CHECK (amount >= 0),
    depositor               BLOB    NOT NULL CHECK (length(depositor) = 32),
    max_fee                 INTEGER NOT NULL CHECK (max_fee >= 0),
    hook_data               BLOB    NOT NULL,
    -- attestation (owner: resolver)
    nonce                   BLOB    CHECK (nonce IS NULL OR length(nonce) = 32),
    attestation_status      TEXT    NOT NULL DEFAULT 'unseen'
                            CHECK (attestation_status IN ('unseen', 'pending', 'complete')),
    fee_executed            INTEGER,
    finality_threshold_executed INTEGER,
    delay_reason            TEXT,
    iris_destination_tx     TEXT,                     -- informational; never used to match
    attested_at             INTEGER,                  -- first poll that saw 'complete'
    last_polled_at          INTEGER,
    next_poll_at            INTEGER NOT NULL DEFAULT 0,
    poll_count              INTEGER NOT NULL DEFAULT 0,
    UNIQUE (source_domain, tx_id, event_index)
);
CREATE UNIQUE INDEX burns_by_nonce   ON burns (source_domain, nonce) WHERE nonce IS NOT NULL;
CREATE INDEX        burns_tail       ON burns (source_domain, finalized, height);
CREATE INDEX        burns_poll_queue ON burns (next_poll_at) WHERE attestation_status <> 'complete';

CREATE TABLE receives (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    -- identity and location (owner: ingest)
    domain                  INTEGER NOT NULL,         -- destination chain = where the receive happened
    tx_id                   TEXT    NOT NULL,
    event_index             INTEGER NOT NULL,
    height                  INTEGER NOT NULL,
    block_hash              TEXT,
    block_time              INTEGER NOT NULL,
    finalized               INTEGER NOT NULL CHECK (finalized IN (0, 1)),
    -- message fields (owner: ingest)
    source_domain           INTEGER NOT NULL,
    nonce                   BLOB    NOT NULL CHECK (length(nonce) = 32),
    sender                  BLOB    NOT NULL CHECK (length(sender) = 32),
    caller                  BLOB    NOT NULL CHECK (length(caller) = 32),
    finality_threshold_executed INTEGER NOT NULL,
    burn_token              BLOB    NOT NULL CHECK (length(burn_token) = 32),
    mint_recipient          BLOB    NOT NULL CHECK (length(mint_recipient) = 32),
    amount                  INTEGER NOT NULL,
    depositor               BLOB    NOT NULL CHECK (length(depositor) = 32),
    max_fee                 INTEGER NOT NULL,
    fee_executed            INTEGER NOT NULL,
    expiration_block        INTEGER NOT NULL,
    hook_data               BLOB    NOT NULL,
    -- orphan source lookup (owner: resolver)
    source_lookup           TEXT CHECK (source_lookup IN ('unknown_to_iris', 'source_not_found', 'postponed',
                                                          'pre_start', 'missed', 'iris_mismatch', 'double_mint', 'unresolved')),
    source_lookup_count     INTEGER NOT NULL DEFAULT 0,
    next_lookup_at          INTEGER NOT NULL DEFAULT 0,
    iris_source_tx          TEXT,
    UNIQUE (domain, tx_id, event_index)
);
CREATE INDEX receives_by_nonce ON receives (source_domain, nonce);
CREATE INDEX receives_tail     ON receives (domain, finalized, height);

-- Append-only audit of rollbacks. Owner: ingest.
CREATE TABLE rollbacks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       INTEGER NOT NULL,
    event_type   TEXT    NOT NULL CHECK (event_type IN ('burn', 'receive')),
    tx_id        TEXT    NOT NULL,
    event_index  INTEGER NOT NULL,
    height       INTEGER NOT NULL,
    block_hash   TEXT,
    scope        TEXT    NOT NULL CHECK (scope IN ('tail', 'final')),
    detected_at  INTEGER NOT NULL
);

-- Alert conditions and their delivery state. Owners: monitor (condition columns), notifier (delivery columns).
CREATE TABLE alerts (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    kind               TEXT    NOT NULL,
    subject            TEXT    NOT NULL,
    severity           TEXT    NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    message            TEXT    NOT NULL,
    first_seen_at      INTEGER NOT NULL,
    opened_at          INTEGER NOT NULL,              -- set on open and on a throttled re-open
    last_seen_at       INTEGER NOT NULL,
    resolved_at        INTEGER,
    notified_at        INTEGER,
    notify_attempts    INTEGER NOT NULL DEFAULT 0,
    last_notify_error  TEXT,
    UNIQUE (kind, subject)
);
CREATE INDEX alerts_open ON alerts (id) WHERE resolved_at IS NULL;

-- Final rows are append-only (I3). The application never needs these to fire.
CREATE TRIGGER burns_final_no_delete BEFORE DELETE ON burns WHEN OLD.finalized = 1
BEGIN SELECT RAISE(ABORT, 'invariant I3: finalized burn rows cannot be deleted'); END;
CREATE TRIGGER burns_final_immutable BEFORE UPDATE OF
    source_domain, tx_id, event_index, height, block_hash, block_time, finalized,
    destination_domain, sender, recipient, destination_caller, min_finality_threshold,
    burn_token, mint_recipient, amount, depositor, max_fee, hook_data
ON burns WHEN OLD.finalized = 1
BEGIN SELECT RAISE(ABORT, 'invariant I3: finalized burn rows are immutable'); END;
CREATE TRIGGER receives_final_no_delete BEFORE DELETE ON receives WHEN OLD.finalized = 1
BEGIN SELECT RAISE(ABORT, 'invariant I3: finalized receive rows cannot be deleted'); END;
CREATE TRIGGER receives_final_immutable BEFORE UPDATE OF
    domain, tx_id, event_index, height, block_hash, block_time, finalized,
    source_domain, nonce, sender, caller, finality_threshold_executed, burn_token,
    mint_recipient, amount, depositor, max_fee, fee_executed, expiration_block, hook_data
ON receives WHEN OLD.finalized = 1
BEGIN SELECT RAISE(ABORT, 'invariant I3: finalized receive rows are immutable'); END;

-- Matching (ADR 0008). A transfer exists from the moment of the burn.
CREATE VIEW transfers AS
SELECT
    b.id AS burn_id, r.id AS receive_id,
    b.source_domain, b.destination_domain, b.nonce,
    b.tx_id AS burn_tx, b.height AS burn_height, b.block_time AS burn_time, b.finalized AS burn_finalized,
    r.tx_id AS receive_tx, r.height AS receive_height, r.block_time AS receive_time, r.finalized AS receive_finalized,
    b.amount, b.max_fee, r.fee_executed, b.min_finality_threshold,
    b.attestation_status, b.attested_at, b.delay_reason,
    CASE WHEN r.id IS NOT NULL THEN 'completed'
         -- 60 = COVERAGE_MARGIN_SECS (store/mod.rs); a test asserts they match
         WHEN b.attestation_status = 'complete' AND b.block_time < d.start_time + 60 THEN 'pre_window'
         WHEN b.attestation_status = 'complete' THEN 'attested'
         ELSE 'burned' END AS state,
    r.block_time - b.block_time AS latency_secs
FROM burns b
LEFT JOIN receives r ON r.source_domain = b.source_domain AND r.nonce = b.nonce
LEFT JOIN chain_state d ON d.domain = b.destination_domain;
