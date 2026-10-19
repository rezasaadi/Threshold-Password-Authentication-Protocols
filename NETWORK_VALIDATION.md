> Historical baseline record (2026-10-05 or earlier). These results describe
> the earlier implementation. Current source validation is documented in
> [docs/validation/README.md](docs/validation/README.md).

# Validation and raw smoke evidence

Validation date: 2026-10-05. These are small execution checks on the same
Windows/Ubuntu WSL2 machine, not the eventual paper comparison coordinates.

## Build and tests

The final Linux commands, inside this repository, both passed:

```sh
cargo test --locked --workspace --all-targets
cargo build --locked --release --workspace --all-targets
```

**96 tests passed**, including 22 preserved RoUpSPA protocol tests, four gap
regressions, eight RoUpSPA process tests, three baseline process tests, two
harness process tests in local socket mode, and nine transport tests. Full logs:
`results/linux-final-tests.log` and `results/linux-final-build.log`.
Windows `cargo build --locked --release --bin bench_network` passed too; see
`results/windows-final-build.log`. The baseline Windows full workspace failure
was the preserved SSH crate's absent OpenSSL, described in `BASELINE.md`.
The full Linux workspace successfully builds that crate.

Twelve protected files (the original quorum protocol modules, original RoUpSPA
integration test, and `.tex` files in the code archive) were checked byte-identical
against `crates.zip`. No Python script or manuscript edit was created.

## Final real namespace runs

Each run used separate client/provider/verifier namespaces and independent
processes, with actual TCP and endpoint `tc netem`. Smoke parameters are
`(n_sp,t_sp,q_sp)=(4,2,3)`, requested egress delay 0.25 ms per direction, zero
jitter, and 100 Mbit/s bandwidth. Actual `tc` output shows 249 microseconds on
this host. Connection policy is fresh TCP per request, including connect time.
Authentication has one warm-up/two samples per scheme; the other configurations
have zero warm-ups/one sample. All have one repetition.

| Operation/schedule | Observed outcome | Result directory under `network-results/` |
| --- | --- | --- |
| Authentication, three schemes | 2/2 completed each | `run-1791163846025753309` |
| Registration, three schemes | 1/1 completed each under documented scheme return rules | `run-1791163990361727820` |
| Password Update, three schemes | 1/1 completed each | `run-1791164120264138111` |
| RoUpSPA Secret Update | 1/1 completed | `run-1791164214846885844` |
| RoUpSPA Authentication, 2% netem loss | 1/1 completed; actual kernel drops recorded | `run-1791164240385667312` |
| Entire login Store suppressed | Registration unresolved; same session resumed/completed after service restart | `run-1791164269114396498` |
| Client crash after provider writes | Registration unresolved; new client resumed/completed same session | `run-1791164297016698408` |
| Provider stop/return | Authentication completed with one stopped provider; restart/own-share identification repair and later Authentication recorded | `run-1791164324361672804` |
| Identification synchronization | 1/1 completed; 32 measured messages include peer traffic | `run-1791164350972386582` |

Each directory contains `raw.jsonl`, Rust-generated `summary.json`, and
`session-outcomes.json` for all fixture/warm-up/measured/recovery outcomes.
Durable role/client state and endpoint/peer/process logs are beneath
`network-state/`. `environment.json` records CPU, machine, kernel, Rust, binary
digest and measurement policy. `*-network.json` and `*-network-final.json`
record exact setup commands, observed ping RTT, and actual qdisc settings and
counters. Loss-run final qdisc snapshots record 13 total packet drops.
The composed 2% loss is represented as `2.0000000000000018` in JSON due to
floating-point representation; `tc` confirms an actual 2% setting.

The original crash/suppression attempts stay unresolved in their denominators
even after successful recovery. Both resumed sessions were checked against the
original session IDs. Killed-client rows explicitly mark unavailable client
CPU/retry/prefix telemetry and retain available endpoint observations instead.
Terminal delivery remains one-way; independent durable logs establish processing.

## Exact command policy

The CLI commands were, in order:

```sh
bench_network smoke --config config/network-smoke.json
bench_network compare --config config/network-registration-smoke.json
bench_network compare --config config/network-password-smoke.json
bench_network compare --config config/network-secret-smoke.json
bench_network compare --config config/network-loss-smoke.json
bench_network fault --config config/network-terminal-fault-smoke.json
bench_network fault --config config/network-client-restart-smoke.json
bench_network fault --config config/network-provider-restart-smoke.json
bench_network compare --config config/network-sync-smoke.json
```

Commands ran under Ubuntu WSL2 with namespace privileges. Native Linux
execution uses `sudo target/release/bench_network` after a source build.
Logs are retained in `results/release-*-smoke.log`. The recorded kernel is
`6.6.87.2-microsoft-standard-WSL2`, with Rust/Cargo `1.93.0`.

The measured executable BLAKE3 digest is
`16ae7b9d13d84e5003ccf600d7ac2181a6d168d0eb736460c6dc92a12787a265`.
Executables must be rebuilt from the source revision being evaluated.

After all runs, namespace inventories before/after were identical (both empty),
no experiment bridges remained, and no `bench_network` process remained.
Evidence: `results/cleanup-verification.txt`, `results/namespaces-*.log`,
`results/bridges-after.log`, and `results/services-after.log`.
Earlier debug/local runs are retained as development evidence. Frequency/turbo
was not controlled, and the sample counts are not statistically adequate for a
paper comparison. `PROTOCOL_GAPS.md` documents the reproduced old-password and
uncommitted-account problems; passing smoke checks does not establish security.
