# Unified UpSPA Paper Benchmark

This repository provides one reproducible Rust benchmark for four password-authentication constructions used in the paper:

| CLI scheme | Implementation included | Main measured phases |
|---|---|---|
| `upspa` | latest UpSPA benchmark path, including lightweight password update v2 | setup, registration, authentication, secret update, password update |
| `pastau` | PAS-TA-U with Ristretto TOPRF and threshold BLS token generation | setup, registration, authentication, password update, verification primitives |
| `augsso` | registration-corrected AUGSSO with password update | setup, registration, authentication, password update |
| `upspa-quorum` | admissible ABD-style quorum variation of UpSPA | registration, secret update, password update |

`bench_unified` is the only executable interface. It validates one parameter grid, applies the same timing and network settings to every selected scheme, runs the scheme engines sequentially, and writes one normalized whitespace-separated result file.

The code is intended for research benchmarking and protocol comparison. It is not a production authentication service.

## Quick start

Requirements:

- Rust 1.93.0 through `rust-toolchain.toml` (the crate language floor is 1.75)
- Cargo
- a native linker and C build toolchain

On Windows with the default MSVC Rust target, install Visual Studio Build Tools with **Desktop development with C++**. WSL with a Linux Rust toolchain is also supported.

Build the pinned dependency set:

```bash
cargo build --locked --release --bin bench_unified
```

Inspect a run without executing benchmarks:

```bash
cargo run --locked --release --bin bench_unified -- \
  --scheme all \
  --kind all \
  --nsp 20 \
  --tsp 12 \
  --dry-run
```

Run the paper configuration with explicit `NSP` and `TSP` values:

```bash
cargo run --locked --release --bin bench_unified -- \
  --scheme all \
  --kind all \
  --net all \
  --nsp NSP \
  --tsp TSP \
  --sample-size 200 \
  --warmup-iters 50 \
  --proc-warmup 200 \
  --proc-samples 1000 \
  --lan-rtt-ms 0.5 \
  --lan-jitter-ms 0.05 \
  --lan-bw-mbps 1000 \
  --wan-rtt-ms 60 \
  --wan-jitter-ms 5 \
  --wan-bw-mbps 50 \
  --overhead-bytes 64 \
  --offline max \
  --pwdupd v2 \
  --out results/paper_bench.dat
```

Replace `NSP` and `TSP` with positive integers satisfying `1 <= TSP <= NSP`. The quorum benchmark uses the maximum admissible number of offline providers by default; `--offline max` is shown explicitly so the experimental condition is visible in the command.

## Unified benchmark kinds

The baseline schemes (`upspa`, `pastau`, and `augsso`) support:

| Kind | Measurement |
|---|---|
| `proto` | measured client-side protocol computation |
| `prim` | measured cryptographic primitive microbenchmarks |
| `sp` | measured server/provider computation and in-memory storage operations |
| `net` | modeled network time with server processing set to zero |
| `full` | measured client computation plus modeled network time and calibrated server p50 processing |

The quorum scheme supports:

| Kind | Measurement |
|---|---|
| `full-no-net` | complete local quorum protocol with real cryptographic work and provider state transitions, without artificial network delay |
| `full-net` | the same local execution plus LAN or WAN message-level simulation |
| `quorum-overhead` | ABD synchronization overhead for quorum write and stale-provider recovery |

`--kind all` selects every applicable kind. If a selected kind does not apply to a selected scheme, that scheme is skipped for that kind. Quorum authentication is intentionally absent because the updated online authentication path is quorum-free.

## Parameter contract

All list values are comma-separated. The unified runner rejects unknown flags, empty lists, invalid thresholds, zero sample counts, invalid network values, and inadmissible explicit offline counts before starting a benchmark.

| Flag | Accepted values | Default | Scope |
|---|---|---|---|
| `--scheme` | `all`, `upspa`, `pastau`, `augsso`, `upspa-quorum`; comma lists allowed | `all` | scheme selection |
| `--kind` | `all`, `proto`, `prim`, `sp`, `net`, `full`, `full-no-net`, `full-net`, `quorum-overhead` | `all` | benchmark selection |
| `--ops` | `all` or a list of `reg`, `secupd`, `pwdupd` | `all` | quorum phases |
| `--nsp` | positive integer list | `20,40,60` | provider counts |
| `--tsp` | integer list with `1 <= tsp <= nsp` | unset | absolute thresholds |
| `--tsp-pct` | integer percentage list in `1..=100` | `60` | thresholds computed as `ceil(nsp * pct / 100)` |
| `--sample-size` | positive integer | `200` | timed observations per row |
| `--warmup-iters` | nonnegative integer | `50` | warmup observations per row |
| `--proc-warmup` | nonnegative integer | `200` | server p50 calibration warmup |
| `--proc-samples` | positive integer | `1000` | server p50 calibration samples |
| `--rng-in-timed` | switch | off | include applicable RNG work in timed client/server regions |
| `--net` | `lan`, `wan`, `all` | `all` | network profiles |
| `--lan-rtt-ms` | finite nonnegative number | `0.5` | LAN round-trip latency |
| `--lan-jitter-ms` | finite nonnegative number | `0.05` | LAN bounded jitter |
| `--lan-bw-mbps` | finite positive number | `1000` | LAN bandwidth |
| `--wan-rtt-ms` | finite nonnegative number | `60` | WAN round-trip latency |
| `--wan-jitter-ms` | finite nonnegative number | `5` | WAN bounded jitter |
| `--wan-bw-mbps` | finite positive number | `50` | WAN bandwidth |
| `--overhead-bytes` | nonnegative integer | `64` | framing overhead added to each message |
| `--offline` | `max`, `none`, or a nonnegative integer | `max` | quorum provider unavailability |
| `--pwdupd` | `v1`, `v2`, `both` | `v2` | UpSPA password-update variant |
| `--out` | file path | `results/unified_bench.dat` | unified output |
| `--dry-run` | switch | off | validate and print the resolved configuration only |

`--tsp` and `--tsp-pct` are mutually overriding: the last one on the command line selects the threshold mode. With multiple `nsp` and absolute `tsp` values, the benchmark evaluates their Cartesian product. Every absolute threshold must therefore be valid for every selected `nsp`. Use separate commands when the experiment requires paired rather than Cartesian configurations.

Compatibility aliases are accepted for `--samples`, `--warmup`, `--rng`, `--schemes`, and `--unavailable`.

## Quorum condition and offline providers

For quorum-based UpSPA, the storage-provider quorum is

```text
qsp = ceil((nsp + tsp) / 2)
```

The implementation enforces:

```text
1 <= tsp <= qsp <= nsp
2 * qsp - nsp > tsp - 1
```

The full phase needs both `qsp` available storage providers and `tsp` available TOPRF providers. Therefore:

```text
offline_max = nsp - qsp
```

For example, `nsp=20` and `tsp=11` produce `qsp=16`, so `--offline max` runs with four unavailable providers. An explicit count greater than four is rejected before execution.

Quorum writes update only the selected live quorum. A non-quorum provider can remain stale, and the recovery path reads a quorum and installs the freshest counter value. Password update uses the updated lightweight construction: TOPRF under the old and new password with unchanged provider shares, re-encryption of `cipherid`, one signature, and a quorum write of the signed master record.

## Network model

The network simulator operates at the message level. Each transfer includes:

- one-way propagation time equal to `RTT / 2`;
- deterministic pseudorandom bounded jitter;
- serialization time derived from payload bytes, framing overhead, and configured bandwidth;
- protocol-specific fan-out/fan-in and round structure;
- provider processing p50 only for `full` rows.

`net` rows contain no server processing. `full` rows are modeled totals, not wall-clock socket measurements. The quorum `full-net` path adds the same style of network model to a complete locally executed state transition.

## Determinism and timing

Protocol fixtures and simulated jitter use deterministic BLAKE3-derived ChaCha20 seeds. Identical parameters therefore generate identical protocol inputs and network random streams. Runtime measurements still vary with hardware, CPU frequency, operating-system scheduling, and background load.

RNG setup is outside the timed region by default where the source benchmark provides a precomputed path. Use `--rng-in-timed` only when the experiment explicitly includes randomness generation cost. That flag applies to the three baseline schemes; quorum rows report `rng_in_timed=0` because the quorum engine measures complete state transitions under its fixed timing definition.

For paper-quality measurements:

1. build and run with `--release` and `--locked`;
2. use the same host, power policy, CPU affinity, and network parameters for all compared runs;
3. stop unrelated workloads and avoid thermal throttling;
4. run at least three independent processes and report the aggregation rule used in the paper;
5. record CPU, operating system, Rust version, commit hash, and the complete command line.

## Output format

The output is UTF-8, whitespace-separated, one header followed by one row per operation:

```text
scheme kind op net_profile rng_in_timed nsp tsp qsp unavailable samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns
```

| Column | Meaning |
|---|---|
| `scheme` | `upspa`, `pastau`, `augsso`, or `upspa_quorum` |
| `kind` | benchmark kind using underscore form in data rows |
| `op` | scheme-specific operation label |
| `net_profile` | `lan`, `wan`, or `none` |
| `rng_in_timed` | `1` when applicable RNG work is timed, otherwise `0` |
| `nsp`, `tsp` | provider count and threshold; parameter-independent primitive rows may use zero |
| `qsp` | quorum size, or zero for baseline schemes |
| `unavailable` | offline provider count, or zero for baseline schemes |
| `samples`, `warmup` | observations used for the row |
| `min_ns`, `p50_ns`, `p95_ns`, `max_ns` | order statistics in nanoseconds |
| `mean_ns`, `stddev_ns` | arithmetic mean and sample standard deviation in nanoseconds |

Operation labels are preserved from each validated scheme implementation so older paper scripts can map rows without losing phase detail. The separate `net_profile` column removes the need to infer LAN/WAN solely from the operation label.

## Focused runs

Only the baseline schemes with modeled WAN totals:

```bash
cargo run --locked --release --bin bench_unified -- \
  --scheme upspa,pastau,augsso \
  --kind full \
  --net wan \
  --nsp 20,40,60 \
  --tsp-pct 60 \
  --out results/baseline_full_wan.dat
```

Only the quorum experiment at maximum unavailability:

```bash
cargo run --locked --release --bin bench_unified -- \
  --scheme upspa-quorum \
  --kind full-no-net,full-net,quorum-overhead \
  --ops reg,secupd,pwdupd \
  --net all \
  --nsp 20,40,60 \
  --tsp-pct 60,80,100 \
  --offline max \
  --out results/quorum_all.dat
```

Client protocol computation only:

```bash
cargo run --locked --release --bin bench_unified -- \
  --scheme upspa,pastau,augsso \
  --kind proto \
  --nsp 20 \
  --tsp 12 \
  --out results/client_proto.dat
```

## Convenience scripts

The paper preset uses percentage thresholds so every default grid point is admissible:

```bash
./scripts/run-paper.sh
```

```powershell
.\scripts\run-paper.ps1
```

Both scripts accept custom provider grids and output paths; inspect the files for their short positional or named interfaces.

## Docker

Build:

```bash
docker build -t upspa-unified-benchmark .
```

Run with a mounted results directory:

```bash
docker run --rm \
  -v "$PWD/results:/work/results" \
  upspa-unified-benchmark \
  --scheme all \
  --kind all \
  --nsp 20 \
  --tsp 12 \
  --offline max \
  --out results/docker_bench.dat
```

## Repository layout

```text
.
├── Cargo.toml
├── Cargo.lock
├── src/bin/bench_unified.rs
├── crates/
│   ├── upspa/
│   ├── pastau/
│   ├── augsso/
│   └── upspa-quorum/
├── scripts/
├── results/
├── Dockerfile
└── LICENSE
```

The four protocol crates are library-only implementation engines. They are not separate user-facing benchmark binaries. Generated `.dat` and `.txt` files under `results/` are ignored by Git.

## Verification

Run the repository checks before publishing or tagging a paper artifact:

```bash
cargo fmt --all -- --check
cargo test --locked --workspace
cargo build --locked --release --bin bench_unified
```

The repository is initialized locally with no remote. Add a hosting remote only when ready to publish.

## License

MIT. See `LICENSE`.
