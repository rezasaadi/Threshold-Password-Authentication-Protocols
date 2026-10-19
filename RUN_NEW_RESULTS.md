# Earlier focused runner (retained for reference)

**For the complete requested measurement plan, follow
[RUN_ALL_MEASUREMENTS.md](RUN_ALL_MEASUREMENTS.md) and run
`bash run_measurements.sh start`.** The commands below cover the earlier focused
network plan, not all 15 experiments and both exact PDF comparison grids.

Use `bench_network` through the commands below. The existing result files are
historical; this revision contains no new Rust or network measurements.

## 1. Build and check

Run from this repository on Linux with the pinned Rust 1.93.0 toolchain,
Python 3.9+, a C build toolchain, OpenSSL development files, `ip`, `tc`, and
`ping`. Use fresh state/output directories. The commands below create new,
timestamped output directories automatically.

```sh
cargo test --locked --workspace --all-targets
cargo build --locked --release --bin bench_network
python3 -m unittest discover -s scripts -p 'test_paper_tools.py' -v
VALIDATE_ONLY=1 ./run_all_paper_raw.sh preflight paper-minor
```

Stop and resolve any build, test, or validation failure before measuring.
To inspect the plan without Rust or network privileges:

```sh
DRY_RUN=1 ./run_all_paper_raw.sh preflight paper-minor
```

## 2. Preflight, then measure

Use a privileged Linux shell with Cargo on its PATH and permission to create
network namespaces and configure `tc`. The runner does not invoke `sudo`.

```sh
./run_all_paper_raw.sh preflight exp01
./run_all_paper_raw.sh preflight paper-minor
./run_all_paper_raw.sh paper-minor
```

`paper-minor` includes exp01, exp05â€“08, exp10â€“14, and `compare-supported`:
80 configurations and 198 profile/loss/scheme combinations. Preflight uses one
sample and one repetition; it is an execution check, not performance evidence.
The full plan uses the sampling counts saved in `plan.json` and includes fault
cases where aborts or unresolved recovery are expected. It is not a short run.

For only the three-scheme comparison, run:

```sh
./run_all_paper_raw.sh preflight compare-supported
./run_all_paper_raw.sh compare-supported
```

| n | t | q | Read replies r | Required 2tâˆ’1 |
|---:|---:|---:|---:|---:|
| 10 | 4 | 7 | 7 | 7 |
| 20 | 7 | 14 | 13 | 13 |
| 30 | 10 | 20 | 20 | 19 |
| 40 | 14 | 27 | 27 | 27 |
| 50 | 17 | 34 | 33 | 33 |

These points allow the current new-password consistency check to run. They use
a different threshold from the original 60% grid and must be labeled as such.
They do not establish full synchronization security. `compare-scaling` retains
the original 60% grid as a separate diagnostic: its RoUpSPA Password Update
attempts cleanly abort before writing. Do not compare their abort latency with
completed baseline updates.

## 3. Use the evidence

Each run prints its output path. Keep that entire directory. It contains the
plan, source/binary hashes, raw observations, outcomes, and `analysis/` summaries.
The runner automatically summarizes results; regenerate with:

```sh
python3 scripts/summarize_raw.py --input /absolute/path/to/paper-raw-output
```

Report completion rate alongside latency. Keep completed, cleanly aborted,
unresolved, and failed attempts separate; report completed-only latency with
its sample count. Never silently remove failed attempts from denominators.
Use the saved timing/traffic definitions in [PAPER_RUNNER.md](PAPER_RUNNER.md).
The new adapter uses fresh TCP connections, durable storage, and terminal/drain
waits, so its measurements must remain separate from the old modeled figures.

Current build, test, and namespace smoke results are recorded in
[docs/validation/README.md](docs/validation/README.md). The complete performance
matrix requires fresh execution at the selected coordinates and sampling counts.
