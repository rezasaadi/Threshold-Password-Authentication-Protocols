# Necessary code changes

- Added `src/bin/bench_modern.rs`, the isolated modern PAS-TA-U benchmark wrapper. The underlying modern implementation remains the existing, unchanged `crates/pastau` crate.
- Added `src/bin/bench_modern_tcp.rs`: the modern-profile real-TCP benchmark, including parallel threshold calls, token-generation/password-update measurements, reset outside timed regions, and correctness checks.
- Added `pastau_paper/src/bin/bench_paper_tcp.rs`: the equivalent real-TCP benchmark for the paper-style Shoup RSA-2048 profile, with cached setup and the same correctness checks.
- Added `pastau_paper/src/bin/pastau_ssh_agent.rs`: a minimal Unix OpenSSH-agent interface that advertises the paper-style RSA key, accepts RSA-SHA2-256 signing requests, threshold-signs the exact SSH request data, and emits the benchmark row.
- Updated `experiments/run_exp3.sh` only as required to run the supplied SSH experiment reliably: configurable isolated sshd settings, socket readiness, agent-only authorized keys, RSA-SHA2-256 selection, 100 warm-ups plus 100 monotonic timed handshakes, and completed-file resume handling.
- Added `experiments/ssh_test/sshd_config` for the isolated loopback OpenSSH validation service.
- Updated `experiments/process_results.py` so constant-cost modern TTG rows recover `(n,t)` from their result filenames instead of appearing as `(0,0)` in the TTG table.
- Added `pastau_paper` to the workspace and updated the root `Cargo.lock` from the existing dependency manifests during the Linux build.

No protocol implementation, cryptographic profile, or setup JSON file was changed.

Two rejected measurements were preserved, not used in aggregation, under `results/raw/anomalies/`: the initial wall-clock SSH attempt and a WAN80 run during which `tc` was not active. Both were rerun with a monotonic timer and verified network shaping.
