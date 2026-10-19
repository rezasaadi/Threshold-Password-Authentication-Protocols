# Protocol implementation revision

The revised network adapter implements quorum reads, threshold-policy ablation,
subset recovery, randomized contribution consistency, Password Update Discard,
fanout selection, corruption injection, setup comparisons, and phase metrics.

## State transitions and consistency

- Read sets contain `r = n_sp - q_sp + t_sp` responses under the quorum policy.
- Non-verifiable new-password polynomial consistency requires `r >= 2*t_sp - 1`.
  Unsupported coordinates abort before provider writes and preserve the old password.
- The Discard decision is durable before terminal transmission. Resume replays
  Discard and cannot switch to provider writes or Store after a crash.
- A repeated update to the fixed replacement password aborts before reads or writes.
  This does not solve historical-password revocation or every discarded-record
  freshness case.
- Account synchronization collects signed evidence but does not activate an
  account from signatures alone; login-server Store completion is not established.
- Identification synchronization rejects known discarded tuples and higher peer
  counters without locally processed Store evidence. Equal-local-record restart
  repair remains available; general catch-up after a missed Password Update does not.
- Client synchronization is blocked while the client's own operation is unresolved.

## Experiments and metrics

`bench_network capabilities` reports supported phases and restrictions. The
measurement runners rebuild the current source, check capabilities, retain
provenance, and keep completed, cleanly aborted, unresolved, and failed attempts
separate. Experiments exp01 through exp15 and the comparison groups are documented
in `RUN_ALL_MEASUREMENTS.md` and `PAPER_RUNNER.md`.

The supported grid uses `(n,t,q) = (10,4,7), (20,7,14), (30,10,20), (40,14,27),
(50,17,34)`. The original `t=0.6*n` grid remains a separate diagnostic; all five
RoUpSPA Password Update coordinates fail the consistency guard. Their abort
latencies are not completed-update performance measurements.

The consistency check evaluates a linear sum with one scalar multiplication per
contribution, rather than a single optimized multiscalar primitive. Authentication
subset search has no practical worst-case work bound: `(50,30,40)` admits
847,660,528 threshold subsets.

## Validation and limitations

Current validation comprises 108 Rust tests on Linux, 108 Windows-compatible Rust
tests, 34 Python tests, a full Linux release build, and an isolated namespace smoke
run for RoUpSPA, PASTA-U, and AugSSO. Details and logs are in
`docs/validation/README.md`. The full performance matrix has not been rerun.

The transport is research TCP without the confidential authenticated channels
assumed by the manuscript. Persisted fixture credentials and pending transactions
support crash tests; they do not establish a stateless deployment. The local
benchmark engines and the network adapter retain distinct measurement semantics.

General account synchronization and identification catch-up require a justified
completion-evidence design. Recovery requires `q_sp` other providers, so
`q_sp=n_sp` cannot recover by this rule. Earlier password ciphertexts remain useful
with an earlier password because the TOPRF key and long-term secrets are unchanged.
Fresh state directories are required for experiments. An interrupted state without
a recorded Discard decision cannot reconstruct that decision retroactively.
