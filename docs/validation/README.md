# Source validation

Validation date: 19 October 2026. Rust commands used the pinned 1.93.0 toolchain.
Linux checks ran under Ubuntu WSL2; Windows checks used the native MSVC toolchain.

| Check | Result | Evidence |
|---|---|---|
| Linux Rust workspace, all targets | 108 passed | `linux-rust-tests.log` |
| Windows Rust workspace excluding `pastau_paper` | 108 passed | `windows-rust-tests.log` |
| Linux process regressions after test deadline adjustments | 15 passed | `linux-process-tests-final.log` |
| Linux release build, full workspace and all targets | Passed | `linux-release-build.log` |
| Python runner and evidence tests | 34 passed | `validation-summary.json` |
| Shell syntax | 7 entry points passed | `linux-runtime-validation.json` |
| Smoke configuration validation | 9 passed | `linux-runtime-validation.json` |
| Isolated namespace/tc Authentication smoke | All three schemes completed | `linux-runtime-validation.json` |
| Host namespace inventory after the smoke run | Unchanged | `linux-runtime-validation.json` |

```sh
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo build --locked --release --workspace --all-targets
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

On Windows without native OpenSSL, the test command excludes `pastau_paper`:

```sh
cargo test --locked --workspace --exclude pastau_paper --all-targets
```

The network harness success fixture uses `(n,t,q)=(4,2,3)`, so `r=3` satisfies
the new-password consistency bound. Process tests allow longer deadlines on
Windows for concurrent startup and durable writes. These are test settings;
production timeout and protocol rules are unchanged.

The namespace smoke used the freshly compiled debug executable, one measured
Authentication sample per scheme, and the small profile in
`config/network-smoke.json`. It ran inside private mount and network namespaces.
The saved JSON contains the exact configuration, measured rows, and outcome
summary. This execution check is not a publication-quality performance study.
The full performance matrix has not been rerun.

Historical logs under `results/` and `network-results/` describe earlier revisions.
Absolute host paths in retained logs and metadata are normalized as documented in
`../ARTIFACT_STRUCTURE.md`; timing values, counts, and outcomes are unchanged.
