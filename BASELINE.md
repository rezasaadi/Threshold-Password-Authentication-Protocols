# Historical build baseline

The initial code baseline is identified by the `crates.zip` digest in
`SOURCE_ARCHIVES.txt`. Historical Windows full-workspace tests failed in
`openssl-sys` because the `pastau_paper` SSH executable requires native OpenSSL.
The diagnostic log is `baseline-test.log`. Excluding `pastau_paper` passed the
Windows tests, including the 22 original RoUpSPA protocol integration tests;
the corresponding log is `baseline-protocol-tests.log`.

The repository pins Rust 1.93.0 through `rust-toolchain.toml`. The earlier Linux
baseline used Ubuntu under WSL2, OpenSSL 3.0.13, and kernel
6.6.87.2-microsoft-standard-WSL2. Network namespace checks required elevated
Linux privileges. Current build and test results are recorded in
[docs/validation/README.md](docs/validation/README.md).
