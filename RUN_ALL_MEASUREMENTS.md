# Full measurement workflow

From the extracted repository on Linux:

```bash
bash run_measurements.sh start
```

The launch command may require one initial sudo authorization. The runner detaches, builds both
benchmarks from this source, checks the Python orchestration, validates every
configuration, probes isolated networking, and runs the jobs **serially**.
The worker continues after the terminal closes. The host must remain powered on
and awake. Suspend,
shutdown, storage exhaustion, or loss of required permissions can interrupt work.
No further password prompts occur.

Required before launch: the pinned Rust 1.93.0 toolchain and its dependencies,
Python 3.9+, a C build toolchain, OpenSSL development files, `ip`, `tc`, `ping`,
`unshare`, and `mount`. Network experiments require Linux privileges permitting
network and mount namespaces and netem; restricted containers may deny these.
First-time Cargo builds need access to the dependency registry.

## What it runs

| Group | Coverage | Jobs |
|---|---|---:|
| RoUpSPA alone | All existing experiments exp01â€“exp15, unchanged coordinates, profiles, faults and sampling | 89 |
| UpSPA / PASTA-U / AugSSO | All 27 PDF coordinate pairs, three schemes each | 81 |
| UpSPA / RoUpSPA | All five PDF triples, two schemes each | 10 |
| Total | All three groups | 180 |

A job contains multiple phases or network profiles where the existing benchmark
supports them; 180 is not the number of individual timed samples.

Exact baseline pairs from PDF printed pages 33â€“39:

- Deployment: `(3,2), (5,2), (5,4), (7,2), (7,3), (7,5), (7,7)`.
- Fixed provider count: `(10,t)` for every `t=1,...,10`.
- Proportional threshold: `(n,0.6n)` for `n=10,20,...,100`.

Exact UpSPA/RoUpSPA triples from printed pages 40â€“41:
`(3,2,3), (5,3,4), (7,4,6), (7,5,6), (10,6,8)`.

Baseline phases: registration, authentication and password update; client,
provider, LAN and WAN data. UpSPA/RoUpSPA phases: registration, secret update and
password update; client, LAN and WAN data, plus the available provider output.
PDF comparisons use 50 warmups and 200 samples, RNG excluded; LAN RTT 0.5 ms,
jitter 0.05 ms, 1,000 Mbps; WAN RTT 60 ms, jitter 5 ms, 50 Mbps; 64-byte message
overhead. Provider calibration explicitly uses 50/200 as well (its sample counts
are not specified by the PDF). RoUpSPA uses `--offline max` as in the original
repository README; the PDF does not specify the offline count. This assumption
and all settings are recorded in `plan.json`.

## Interpretation that must be preserved

**The PDF comparisons use the unchanged historical protocol cores with modeled
LAN/WAN costs.** They are not measurements of the revised process/network
adapter. In particular, historical RoUpSPA comparison rows do not exercise the
adapter's revised TOPRF read size, password consistency guard, durable terminal
handlers or fail-closed recovery. Do not present these as updated adapter results.

The separate 15 RoUpSPA experiments run that adapter in real processes and
network namespaces. Coordinates that trigger its consistency guard remain in
the plan; clean aborts and unresolved/failed attempts are recorded, not converted
to successful timings. Fixtures, warmups, primary attempts and recovery are
separate in summaries.

PASTA-U emits provider component timings rather than a phase total. These are
retained individually. AugSSO's native component-median sums are labeled as such;
they are not empirical phase medians or p95s. `comparisons.csv` preserves scope,
raw phase names and the `selected_for_pdf` flag. Use `p50_ns`, not the legacy
`total_ns` column, for reported medians.

No Rust source, Cargo manifest, lockfile or toolchain pin was changed for this
measurement update. The older `run_all_paper_raw.sh` commands remain available,
but their `all` / `paper-minor` selections are **not** this combined PDF plan.

## Results and failures

The command prints its output directory, `measurements/run-.../`. Inside:

- `FINAL_STATUS.json` and `RESULTS_SUMMARY.md`: final completeness status.
- `job-status.csv` and `FAILED_JOBS.csv`: every planned job and any failure.
- `comparisons.csv`: validated full PDF comparison rows, with method/scope labels.
- `network_summaries.json`: full network summaries, outcome counts and availability.
- `jobs/`: original raw evidence, endpoint logs, per-job stdout/stderr, and attempts.
- `plan.json`, `source-sha256.json`, `launch-*/build/provenance.json`: exact settings,
  source identities, build command and executable hashes. Binaries are copied
  into each launch directory to prevent another build replacing them during a run.
- `master.log` and `progress.json`: ongoing progress.

`COMPLETE` means all planned evidence was captured; it does **not** mean all
protocol attempts succeeded. A failed/timed-out job is recorded and later jobs
continue. A build failure blocks measurement. If network privileges fail, the
independent PDF jobs still run and the final status is `INCOMPLETE`.

Every measurement job has a four-hour deadline; builds have two hours. These
are safety bounds, not runtime estimates. Change a bound before starting if
needed, e.g. `MEASUREMENT_JOB_TIMEOUT_SECONDS=28800 bash run_measurements.sh start`.
No whole-run time estimate is claimed; all 15 suites can take substantial time.
Per-coordinate sample preflights are optional via `MEASUREMENT_PREFLIGHT=1`;
default launch already validates every configuration and probes networking.

Optional commands:

```bash
# Inspect the full plan without building or acquiring privileges.
bash run_measurements.sh plan > measurement-plan.json

# Inspect the saved status.
bash run_measurements.sh status /absolute/path/to/measurements/run-...

# Resume after interruption; complete evidence is rechecked and skipped.
bash run_measurements.sh resume /absolute/path/to/measurements/run-...
```

Resume preserves earlier attempts and retries missing/failed jobs in new
folders. It requires the same source files, unchanged plan and identical rebuilt executable
hashes, and uses the saved settings; it does
not combine measurements across edited implementations. One worker at a time
is permitted. No automatic reboot/startup service is installed.

## Validation scope

All 34 Python orchestration and synthetic evidence checks pass. The source also
passes the Linux and Windows-compatible Rust suites and a full Linux release
build. A small isolated namespace run completed for all three network schemes.
The exact checks and logs are recorded in `docs/validation/README.md`.

These checks do not replace the full measurement matrix. The launch command
builds and checks the source and executable again before collecting measurements.
Historical result files are not new performance results for this revision.
