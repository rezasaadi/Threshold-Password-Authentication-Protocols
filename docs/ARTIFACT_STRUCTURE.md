# Research artifact structure

- `crates/`: protocol implementations and protocol-level tests.
- `src/`: unified benchmark CLI, process adapters, and network harness.
- `tests/`: process, transport, and fault/recovery regression tests.
- `config/`: small phase and fault smoke configurations.
- `scripts/`, `experiments/`, and root shell entry points: experiment planning,
  execution, evidence checks, and result processing.
- `pastau_paper/`: paper-style PAS-TA-U implementation and SSH experiment.
- `results/` and `network-results/`: historical measurements and diagnostic logs.
- `docs/validation/`: source build/test results and a small namespace smoke check.
- `SOURCE_ARCHIVES.txt`: original input archive identifiers and SHA-256 digests.
- `SOURCE_SHA256.json`: SHA-256 digests of the current source and build definitions.

Executables are built from source. Historical measurements remain labeled by their
original runs and do not establish performance or security of a later revision.
Protocol restrictions are retained in `PROTOCOL_GAPS.md` and `REVISION_NOTES.md`.

Absolute build and working-directory paths in archived metadata and diagnostic logs
are replaced by `<repository>`, `<workspace>`, `<build-directory>`, `<cargo-home>`,
or `<user-home>`. These replacements affect path strings only. Recorded measurement
values, counters, configurations, and outcomes are preserved. The normalized files
are not byte-identical copies of the original logs; archive digests identify the
original input packages. Raw numeric data files are unchanged.
