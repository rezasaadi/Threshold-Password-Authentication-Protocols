# PAS-TA-U three-way benchmark results

These results compare three distinct sources:

- **Modern Rust PAS-TA-U**: Reza Saadi's BLS12-381 implementation in `crates/pastau`.
- **Paper-style Rust PAS-TA-U**: the Rust reproduction in `pastau_paper`, using the paper's Shoup RSA-2048 profile.
- **Published PAS-TA-U**: values reported by the original PAS-TA-U evaluation, whose implementation/environment used Python and OpenSSH.

The Rust results were collected under Ubuntu 24.04.3 LTS in WSL2 on an Intel Core i9-14900HX with Rust 1.93.0. Every point is the arithmetic mean of three independent runs; each run used 100 warm-ups and 100 timed samples. Real TCP experiments used Linux `tc` with 2 ms one-way delay for LAN4 and 40 ms one-way delay for WAN80.

Because the published values come from the paper's original environment, the final column is a cross-environment reference, not a same-machine rerun. The paper does not publish separate TTG PartEval, Combine, and Verify values, so it is absent from the isolated TTG table.

## Isolated TTG (ms)

| `(t,n)` | Implementation | Profile | PartEval/SP | Combine/client | Verify |
|---|---|---|---:|---:|---:|
| `(2,3)` | Modern Rust | BLS12-381 | 0.461 | 0.474 | 2.184 |
| `(2,3)` | Paper-style Rust | Shoup RSA-2048 | 2.484 | 1.163 | 0.089 |
| `(3,6)` | Modern Rust | BLS12-381 | 0.441 | 0.699 | 2.159 |
| `(3,6)` | Paper-style Rust | Shoup RSA-2048 | 2.538 | 1.285 | 0.091 |
| `(5,10)` | Modern Rust | BLS12-381 | 0.461 | 1.195 | 2.210 |
| `(5,10)` | Paper-style Rust | Shoup RSA-2048 | 2.494 | 1.915 | 0.094 |
| `(10,10)` | Modern Rust | BLS12-381 | 0.443 | 2.411 | 2.172 |
| `(10,10)` | Paper-style Rust | Shoup RSA-2048 | 2.494 | 3.498 | 0.090 |

## Complete token generation (ms)

| Network | `(t,n)` | Modern Rust | Paper-style Rust | Published PAS-TA-U |
|---|---|---:|---:|---:|
| LAN4 | `(2,3)` | 5.948 | 19.559 | 22.8 |
| LAN4 | `(3,6)` | 6.451 | 19.698 | 25.1 |
| LAN4 | `(5,10)` | 7.157 | 23.322 | 28.2 |
| LAN4 | `(10,10)` | 9.696 | 38.075 | 32.5 |
| WAN80 | `(2,3)` | 86.277 | 100.490 | 109.5 |
| WAN80 | `(3,6)` | 86.025 | 101.755 | 112.4 |
| WAN80 | `(5,10)` | 85.141 | 104.152 | 115.8 |
| WAN80 | `(10,10)` | 90.192 | 115.375 | 119.9 |

## Complete password update (ms)

| Network | `(t,n)` | Modern Rust | Paper-style Rust | Published PAS-TA-U |
|---|---|---:|---:|---:|
| LAN4 | `(2,3)` | 25.532 | 54.780 | 65.3 |
| LAN4 | `(3,6)` | 26.304 | 55.458 | 74.4 |
| LAN4 | `(5,10)` | 29.056 | 66.370 | 82.7 |
| LAN4 | `(10,10)` | 31.743 | 99.079 | 95.1 |
| WAN80 | `(2,3)` | 339.986 | 377.231 | 325.5 |
| WAN80 | `(3,6)` | 339.165 | 378.775 | 333.1 |
| WAN80 | `(5,10)` | 341.851 | 388.589 | 346.9 |
| WAN80 | `(10,10)` | 345.343 | 416.835 | 357.6 |

## OpenSSH-agent validation (ms)

| Network | `(t,n)` | Paper-style sign service | Complete SSH handshake | Published token generation |
|---|---|---:|---:|---:|
| LAN4 | `(2,3)` | 20.027 | 283.133 | 22.8 |
| LAN4 | `(3,6)` | 25.834 | 295.059 | 25.1 |
| LAN4 | `(5,10)` | 39.992 | 316.739 | 28.2 |
| LAN4 | `(10,10)` | 75.808 | 352.161 | 32.5 |
| WAN80 | `(2,3)` | 22.283 | 1281.183 | 109.5 |
| WAN80 | `(3,6)` | 27.493 | 1283.739 | 112.4 |
| WAN80 | `(5,10)` | 41.661 | 1311.231 | 115.8 |
| WAN80 | `(10,10)` | 74.047 | 1370.666 | 119.9 |

## Artifacts

- `raw/`: all canonical `.dat` measurements and SSH handshake samples.
- `raw/anomalies/`: rejected attempts retained for auditability and excluded from aggregation.
- `processed/`: compact CSV summaries used for analysis.
- `tables/`: publication-ready LaTeX tables.
- `CODE_CHANGES.md`: the necessary implementation and harness changes made for the experiment.

Regenerate the processed artifacts with:

```bash
python3 experiments/process_results.py --root .
```
