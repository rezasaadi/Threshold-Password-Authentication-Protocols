# Paper experiment runner v2

For the short execution sequence for this revision, use
[RUN_NEW_RESULTS.md](RUN_NEW_RESULTS.md). Start with `paper-minor`; the `all`
mode also includes historical ablations and unsupported parameter diagnostics.

The root `run_all_paper_raw.sh` and `scripts/run_all_paper_raw.sh` launch the same
Python runner. The runner requires Python 3.9+, the repository's Rust toolchain,
and, for network measurements, Linux with `ip`, `tc`, `ping`, and permission to
create network namespaces and configure links and netem. It never invokes
`sudo` or prompts for a password. Network commands require a privileged shell; an unprivileged invocation fails clearly.

## Commands

Generate the complete configuration matrix without compiling or measuring:

```sh
DRY_RUN=1 ./run_all_paper_raw.sh PREFLIGHT
```

Rebuild and validate every configuration without running network experiments:

```sh
VALIDATE_ONLY=1 ./run_all_paper_raw.sh preflight
```

From a privileged Linux shell, run one measured sample at every configuration,
profile, loss level, and scheme (no warmups; one repetition):

```sh
./run_all_paper_raw.sh preflight
```

`PREFLIGHT` is also accepted as a mode. To preflight only a suite:

```sh
./run_all_paper_raw.sh preflight exp12
PREFLIGHT=1 ./run_all_paper_raw.sh compare-diagnostic
```

Run the full experiment plan, or select a suite:

```sh
./run_all_paper_raw.sh all
./run_all_paper_raw.sh paper-minor
./run_all_paper_raw.sh exp13
./run_all_paper_raw.sh compare-supported
./run_all_paper_raw.sh compare-scaling
```

Modes are `all`, `paper-minor`, `roupspa`, `exp01` through `exp15`,
`compare-diagnostic`, `compare-scaling`, `compare-supported`, and `compare-all`.
`upspa-secret` was removed because this
source does not contain the claimed UpSPA network adapter. The available
network schemes are RoUpSPA, PASTA-U, and AugSSO.

The complete plan currently contains 173 JSON configurations and 453 measured
profile/loss/scheme combinations in preflight. `paper-minor` contains 80
configurations and 198 combinations; `compare-supported` contains 30
configurations and 120 combinations. Fixture and recovery sessions
are additional work. In particular, preflight includes the 50-provider scaling
point and is not a short smoke test. To check the environment first, select one
small suite such as `preflight exp12`.

## Build and evidence policy

Every non-dry invocation runs `cargo build --locked --release --bin
bench_network`. Cargo may reuse verified build artifacts; the runner does not
skip Cargo based on an existing executable. It obtains the executable path from
Cargo's structured compiler output and requires the version-2 `capabilities`
response. There is no fallback to the old bundled binary, and `NET_BIN` is
rejected. Build failure stops the run. The output retains the build log,
capability response, environment, executable SHA-256, and Rust-source/manifest
SHA-256 hashes.

All generated configurations are validated before the first network run. A
small namespace/netem capability probe follows. A runner failure stops the
suite by default; `CONTINUE_ON_ERROR=1` proceeds to other configurations. This
setting concerns harness execution errors. Protocol outcomes such as `failed`,
`unresolved`, or `cleanly_aborted` are valid observations and do not themselves
stop the experiment plan.

`OUT_ROOT` may select a new or empty output directory. Existing output is not
overwritten. Each configuration retains:

- `raw.jsonl`, `requested-config.json`, and `environment.json`;
- the Rust `summary.json` and `session-outcomes.json`;
- network snapshots, endpoint and synchronization transport logs;
- runner stdout/stderr, process logs, and execution status.

Full underlying run directories are retained by default. `KEEP_FULL_RUNS=0`
removes one only after all required evidence has been collected successfully.
Failed or incomplete run directories remain available. `plan.json`,
`MANIFEST.tsv`, and `run-status.jsonl` describe the intended configurations and
what actually ran. Planned but unrun configurations remain visible as missing
in the availability table.

## Configuration changes and interpretation

The comparison matrices use `q_min = floor((n+t-1)/2)+1`; no configuration uses
`q=0`. The common comparison phases are `setup`, `authentication`, and
`password_update`. Here `setup` means RoUpSPA Setup and baseline registration.
Three-scheme rows use `fanout=minimal`. Separate RoUpSPA-only rows use
`fanout=all`. Minimal fanout may expand after a failure, so it is not an absolute
message cap.

`paper-minor` selects exp01, exp05â€“08, exp10â€“14, and `compare-supported`.
The latter uses `(n,t,q) = (10,4,7), (20,7,14), (30,10,20), (40,14,27),
(50,17,34)`. These satisfy `r=n-q+t >= 2*t-1`, so healthy Password Update is
not blocked by the consistency guard. They represent a different threshold
experiment from the original `t=0.6*n` grid. The original grid remains in
`compare-scaling`; every RoUpSPA Password Update point there is an abort
diagnostic, not a completed-operation performance comparison. "Supported"
describes this guard and does not claim a complete security or recovery proof.

The old E1â€“E11 modes are retained, with the additional `f=3` authentication
boundary in E8. For `(n,t,q)=(7,3,5)`, quorum reads require `r=5` replies; three
stopped providers cause the read to fail before a write. E7 is therefore not a
test of Discard at `f=3`.

| Experiment | Purpose |
| --- | --- |
| exp12 | Password Update with `id_write` suppression at 1, 2, and 3 providers. At 1 or 2 suppressed providers, a five-provider quorum may still complete. At 3, the write quorum is impossible and Discard is exercised. |
| exp13 | 0, 1, or 2 corrupt TOPRF partials for Authentication and Password Update, with both fanout settings. |
| exp14 | All versus minimal fanout for Setup, Registration, Authentication, Secret Update, and Password Update on LAN/WAN profiles. |
| exp15 | Legacy threshold versus quorum reads with 0, 2, 3, or 4 stopped providers, for Authentication and Password Update. |

Two implementation boundaries are deliberately not disguised as measurement
successes. The current account synchronization path remains fail-closed where
signed account records do not establish login-server Store. Post-restart
recovery may therefore remain unresolved. Also, the unverified new-password
consistency check requires `read_size >= 2*t-1`; otherwise RoUpSPA aborts before
writing, even at some valid healthy quorum coordinates. Such configurations
remain in the comparison matrix so their lack of completed updates is visible.
`plan.json` and `MANIFEST.tsv` include explicit warnings. They are not suitable
for a latency comparison that silently excludes unsuccessful operations.

The threshold policy is an ablation, not the claimed quorum-read protocol.
Freshly initialized successful trials do not test whether an undetected stale
replica can accept an old password. These runs do not establish cryptographic
security or a complete malicious-fault availability theorem.

## Summary output

```sh
python3 scripts/summarize_raw.py --input /path/to/paper-output
python3 scripts/summarize_raw.py --input /path/to/run/raw.jsonl --output /path/to/analysis
```

The runner invokes this summarizer on completion and ordinary failure. It
creates one JSON per experiment/configuration, `index.json`, and
`availability.csv`/`availability.md`. Within each JSON, measured, recovery,
fixture, and warmup populations are separate, and scheme, phase, profile, and
loss level are never pooled together.

Success rate is `completed / all measured attempts`. A clean abort is a
distinct unsuccessful outcome, not a completion. Statistics contain p50, p95,
mean, sample standard deviation, min/max, sum, observation count, and missing
count. Percentiles use nearest rank; standard deviation is null for fewer than
two observations. Timing distributions are shown for all observed attempts and
completed-only attempts separately. Nanoseconds are used throughout.

Timing fields include end-to-end time, end-to-end minus the recorded terminal
wait, end-to-end minus drain, client, quorum, provider/login handler, terminal,
drain, repair, and TOPRF combination time. Subtractions remove the measured
components; they do not assume the configured Delta exactly equals the observed
wait. New counters and application bytes/messages have the same statistics.
The client timing is a wall-time residual, not CPU time.

Legacy absent fields and unavailable client telemetry are not converted to
zero. Fixture-blocked attempts count against availability but supply no
invented latency. Endpoint handler totals in fixture/recovery rows are
cumulative snapshots in the current harness; they are labeled accordingly.
After a killed client, recorded end-to-end duration can be external process
wall time; source labels and missing telemetry counts expose that difference.
Application traffic excludes TCP/IP overhead, and endpoint observations after
crashes may omit interrupted prefixes.

## Validation scope

The current source passes 108 Linux Rust tests, 108 Windows-compatible Rust tests,
34 Python orchestration/evidence tests, shell syntax checks, and a full Linux
release build. Nine smoke configurations validate successfully. A small isolated
namespace run completed Authentication for all three network schemes. Logs and
configuration details appear in `docs/validation/README.md`.

The complete preflight and performance matrices have not been rerun. Historical
result files remain historical evidence. Publication measurements require fresh
execution at the selected coordinates and sampling parameters.
