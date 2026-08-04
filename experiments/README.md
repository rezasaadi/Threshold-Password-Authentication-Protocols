# PAS-TA-U three-way experiments

This directory reproduces the PAS-TA-U comparison reported under `results/`:

1. isolated TTG primitives for the modern BLS12-381 and paper-style Shoup RSA-2048 Rust profiles;
2. complete token generation and password update over real TCP sockets with Linux `tc` at 4 ms and 80 ms RTT;
3. paper-style threshold signing through a minimal OpenSSH-agent-compatible Unix socket.

Every `(n,t)` pair `(3,2)`, `(6,3)`, `(10,5)`, and `(10,10)` uses 100 warm-ups, 100 timed samples, and three independent runs. `config.json` also records the published PAS-TA-U values used in the three-way tables.

## Requirements

- Linux or WSL2 with Rust 1.93, Cargo, Python 3, `tc`, OpenSSL development headers, and OpenSSH client/server;
- permission to apply a `netem` qdisc to loopback;
- a local test-only sshd accepting the generated agent key. Never use a production SSH account for this experiment.

The modern implementation is the existing `crates/pastau` crate. The paper-style Rust implementation is in `pastau_paper`.

## Run

Run Experiments 1 and 2 directly:

```bash
bash experiments/run_exp1.sh
bash experiments/run_exp2.sh
```

Experiment 3 expects an isolated sshd. Copy `experiments/ssh_test/sshd_config.example`, replace its placeholders with absolute paths and a test user, generate a disposable host key, start sshd with that configuration, and then run:

```bash
SSH_USER=test-user SSH_TARGET=127.0.0.1 SSH_PORT=22222 \
  bash experiments/run_exp3.sh
```

Run all configured experiments only after the test sshd is ready:

```bash
bash experiments/run_all.sh
```

Regenerate the CSV and LaTeX outputs from the preserved raw files:

```bash
python3 experiments/process_results.py --root .
```

The scripts remove their loopback qdisc on exit. Confirm with `tc qdisc show dev lo` before using the machine for unrelated network measurements.

## Result provenance

- **Modern Rust PAS-TA-U** is this repository's BLS12-381 implementation.
- **Paper-style Rust PAS-TA-U** is the Rust reproduction of the paper's Shoup RSA-2048 profile.
- **Published PAS-TA-U** values are transcribed from the original PAS-TA-U evaluation and were not remeasured on this machine.

Rejected attempts are retained in `results/raw/anomalies/` and excluded by the processor, which reads only `results/raw/*.dat`.
