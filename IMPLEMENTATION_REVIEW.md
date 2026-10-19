> Historical baseline record (2026-10-05 or earlier). These results describe
> the earlier implementation. Current source validation is documented in
> [docs/validation/README.md](docs/validation/README.md).

# Implementation review and validation scope

This file records the independent protocol/transport review performed during
implementation. It distinguishes executable features and observed checks from
security properties or failure schedules that cannot be established by the
protocol. `PROTOCOL_GAPS.md` gives the detailed protocol evidence.

## Preserved implementation and baseline

The original `crates/upspa-quorum/src/protocols/` state machines and 22
`roupspa_protocol.rs` tests remain present. Baseline build/test output was
recorded before implementation in `baseline-test.log` and
`baseline-protocol-tests.log`. Compatibility module `upspa_abd.rs` was not
substituted for the newer implementation. The existing local/modeled benchmark
binaries remain available under their original names.

## Independent review findings

The review identified the following implementation issues while
the network adapter and harness were being built. Source fixes for every row
below were subsequently reviewed. The process/transport regression tests
passed; final full-workspace and release namespace logs determine the exact
historical build's validation status.

| Area | Finding | Required verification |
| --- | --- | --- |
| Fault injection | The common handler initially looked at `kind/stage/op` but missed RoUpSPA's `action`. | Fixed; live suppression regression receives the actual frame, sends no response, and creates no durable transition. |
| Terminal protocol | Error paths could send a formal reply to an otherwise one-way terminal. | Fixed; rejected and malformed Store regressions observe EOF with zero reply bytes and independent rejection evidence. |
| Transport logs | Endpoint metrics were initially logged before sending the reply. | Fixed; endpoint and client sent/received counts match exactly in the regression. |
| Processing totals | RoUpSPA semantic transition rows and common transport rows both contained handler durations. | Fixed in source; summation counts authoritative `transport=true` handler rows once. Semantic rows retain durable-processing evidence. |
| Durable replacement | Removing a prior Windows state file before rename introduced a crash window. | Fixed in source with platform-specific replacement; Linux fsync covers temporary file and parent directory. Process restart tests pass. |
| Recovery scheduling | Requesting recovery simultaneously at every serial service can deadlock peer evidence reads. | Fixed; recovery initiation is sequential while each provider's peer stage remains concurrent. Process recovery tests pass. |
| Read validity | Account reads initially counted signature-valid candidates before authenticated decryption and counter binding. | Fixed in source; signature, AEAD, family, and authenticated-counter checks precede counting toward `t_sp`. |
| Consistent root keys | First-`t_sp` responses with mixed verification keys could abort before a consistent group arrived. | Fixed for the provisioned experiment client using the public verification key pinned during Setup. |
| Internal actions | The provider's catch-all dispatch initially exposed journal-only `restart_stale` and `sync_id_install` actions to socket callers. | Fixed by wire-action allowlist; process regression rejects injected internal actions. |
| Stage concurrency | Password Update terminal connections were initially opened sequentially. | Fixed in source; each terminal round launches concurrent provider sends, retains identical bytes, and waits final Delta. |
| Phase names | Config used `synchronization`, while an initial client branch recognized only `synchronize`. | Fixed; both aliases execute sequential recovery initiation. |
| Unobserved terminal | A bounded-assumption client return could clear pending state despite missing Store under a loss/crash schedule. | Controller checks independently accepted durable transitions, reclassifies unobserved processing as unresolved, and freezes its own client log for exact retry. |

## Protocol tests observed during review

```text
cargo test -p upspa_quorum_bench --test roupspa_protocol_gaps -- --nocapture
```

Four tests passed on 2026-10-05. Raw output is saved in
`results/protocol-gap-tests.log`. They establish:

- Successful old-password Authentication using an undetected missed
  identification threshold after a completed Password Update.
- Stale account selection after Secret Update, followed by honest login-server
  rejection of the old verifier.
- Highest-counter synchronization accepting a signed but uncommitted direct
  account write when an independent recovery context lacks the writing
  client's operation cache.
- The `q_sp=n_sp` recovery boundary: `q_sp` other replies cannot be obtained.

These tests use the preserved local state machine with isolated endpoint
snapshots. They are explicitly **not** transport or namespace measurements.

```text
cargo test --test network_transport -- --nocapture
```

Nine transport tests passed during review; raw output is
`results/network-transport-tests.log`. They cover actual TCP byte and
message accounting, fragmented reads, a truncated response, oversized frame
rejection, error-response accounting, one-way submission, rejected/malformed
terminal requests at a separately launched login process, whole-message
suppression, and independently logged endpoint reply bytes. The complete
workspace test run and namespace results are recorded separately by the
harness.

The implementation team's runs also passed eight RoUpSPA process tests,
three baseline process tests, and two harness process tests in local socket mode.
The latest expanded RoUpSPA run is captured in
`results/network-roupspa-tests.log` (eight passed, zero failed).
The RoUpSPA process matrix covers healthy operations and durable state,
login/provider restart, `q_sp-1/q_sp` retries, `t_sp-1/t_sp` reads, the
`q_sp`-other response boundary, clean pre-write Discard, exact session retries
and conflicts, client crashes before/after stages, provider/login crashes
before/after durable transitions including terminal Store, missing entire
Password Update messages, signed uncommitted direct-account evidence, and
`q_sp=n_sp` recovery failure. Process tests do not claim exhaustive schedules.

Review of restart recovery also found that installing an older completed root
must preserve a locally durable higher tentative Password Update. That
transition was corrected before the final eight-test rerun. A bounded restart
attempt repairs known root families when peers are available, retains each
provider's own share, and separately writes real outbound recovery transport
measurements to `sync-transports.jsonl`. Direct account completion remains the
explicit protocol gap described above.

An initial debug namespace smoke run is saved at
`network-results/run-1791163200515432490`. It completed two measured
Authentication attempts for each of the three schemes on the same Linux host.
That run predates the final review fixes and is retained as debugging evidence.
Use the subsequent release-run records identified by the final README for
current timing/traffic values; this review does not quote initial debug values
as comparison measurements.

## Claims which remain constrained by the protocol

| Property | Boundary |
| --- | --- |
| Provider-local state | Services own only their own journal/share/records. The client cannot update an unreachable provider. Setup necessarily creates and distributes shares; its exact unfinished setup requests may persist until Setup finishes. |
| Ordinary Authentication | It remains read-only with threshold `t_sp`; no larger hidden read quorum or repair stage is added. Undetected live misses expose the documented old-root outcome. |
| Account repair after missed direct writes | Signature, counter, and `q_sp` responses do not prove login-server Store. The network adapter explicitly refuses activation if that completion prerequisite cannot be established. |
| Restart activation | Restart locally marks known provider families stale. Root recovery retains the provider's own share. Account activation after restart is subject to the unresolved completion-evidence gap. |
| All-provider restart | Reading signed stale records as distinct recovery evidence is an explicit adapter policy. It does not make those records active Authentication replies and does not prove completion of direct account writes. |
| Unfinished sessions | A client's durable log serializes operations using that log. It is not distributed exclusion for a second client or a recovering provider. One writer per state directory is the supported execution policy. |
| Terminal completion | A one-way socket write alone proves neither delivery nor handler durability. Outside the bounded live-endpoint assumption, endpoint logs must determine the measured outcome; the client must preserve uncertainty. |
| Channel security | The research transport is framed TCP unless the final README states otherwise. It does not by itself satisfy the manuscript's TLS-like confidential authenticated channel assumption. |
| Abstract TOPRF security | The concrete Ristretto/Shamir implementation has no contribution proofs. Authenticated decryption validates a recovered key, not every individual contribution or every abstract proof assumption. |
| Fault coverage | Passing representative stop/restart tests does not establish an exhaustive schedule of every process crash at every instruction or disk failure. The raw results and individual tests identify which schedules were actually executed. |

The namespace harness is runnable on Linux and must record actual `ip`/`tc`
commands, observed ping output, machine/kernel/Rust versions, connection policy,
and timing definitions. Local socket tests must not be presented as impaired
namespace experiments. Packet-loss schedules, client/provider/login restart
schedules, threshold/quorum boundaries, terminal processing, recovery, and
unsuccessful attempts must be identifiable in the raw records.

No paper comparison grid was chosen. Smoke coordinates only validate execution;
they are not the eventual comparison design.

The historical 2026-10-05 validation passed 96 Linux workspace tests and the full release build.
`NETWORK_VALIDATION.md` identifies nine final release namespace runs, including
actual packet drops, missing terminal processing, exact session recovery,
provider return, and provider-peer transport accounting. Killed clients have
explicitly unavailable client telemetry and observed endpoint traffic; those
fields are not silently represented as complete zero measurements.
