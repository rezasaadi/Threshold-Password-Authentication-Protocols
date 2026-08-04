# PAS-TA-U paper-style Rust profile

This crate is a second PAS-TA-U implementation profile intended to sit beside the existing modern Rust profile used in the UpSPA comparison.

It follows the PAS-TA-U ESKM paper profile as closely as practical in a standalone Rust benchmark:

- 2HashTDH-style TOPRF over a 2048-bit MODP prime-order subgroup;
- SHA-512 for password-to-exponent and SHA-256 for finalization / `h_i`;
- Shoup threshold RSA with a 2048-bit modulus and public exponent 65537;
- AES-128-OFB for encryption of partial RSA signatures and password-update records;
- token generation excludes final verification, while TTG verification is reported separately;
- parameter pairs from the paper: `(t,n)=(2,3),(3,6),(5,10),(10,10)`;
- arithmetic mean over 100 requests;
- 4 ms LAN and 80 ms Internet comparison profiles.

This is a **paper-style Rust reimplementation**, not the authors' exact Python/OpenSSL/OpenSSH socket experiment. The `*_model_ms` columns add the paper RTT profiles to measured local CPU. They do not include Python, TLS, SSH, socket, or process-scheduling overhead.

## Build

```bash
cargo build --release --bin bench_paper
```

## Generate the four rows

Run each pair separately because `n` and `t` are paired:

```bash
cargo run --release --bin bench_paper -- --n 3  --t 2  --samples 100 --setup-file setup_3_2.json
cargo run --release --bin bench_paper -- --n 6  --t 3  --samples 100 --setup-file setup_6_3.json
cargo run --release --bin bench_paper -- --n 10 --t 5  --samples 100 --setup-file setup_10_5.json
cargo run --release --bin bench_paper -- --n 10 --t 10 --samples 100 --setup-file setup_10_10.json
```

The first run for each pair generates and caches a 2048-bit safe-prime Shoup RSA setup. Setup is not included in token-generation or password-update measurements.

## Direct TTG comparison

Compare these output columns with the existing modern PAS-TA-U primitive rows:

- `ttg_part_eval_ms` vs `ttg_part_eval`;
- `ttg_combine_ms` vs `ttg_combine_t`;
- `ttg_verify_ms` vs `ttg_verify`.

Use the same host, release mode, sample count, CPU policy, and RNG timing policy. The result compares **Shoup RSA TTG** with your **BLS TTG**; it is an instantiation comparison, not a pure protocol-design comparison.

## Phase-level comparison with the PAS-TA-U paper

Use:

- `token_lan4_model_ms` / `token_wan80_model_ms` beside Table 1;
- `pwd_update_lan4_model_ms` / `pwd_update_wan80_model_ms` beside Table 2.

Label these as modeled Rust results. Do not state that they reproduce the original end-to-end SSH measurements.
