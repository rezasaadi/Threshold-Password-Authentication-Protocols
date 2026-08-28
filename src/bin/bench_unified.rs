use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

const MODERN_KINDS: [&str; 6] = [
    "client",
    "provider",
    "login_server",
    "full_no_net",
    "net_only",
    "full_net",
];
const HISTORICAL_KINDS: [&str; 5] = ["proto", "prim", "sp", "net", "full"];
const UPSPA_OPS: [&str; 5] = ["setup", "reg", "auth", "secupd", "pwdupd"];
const ROUPSPA_OPS: [&str; 7] = [
    "setup",
    "reg",
    "auth",
    "secupd",
    "pwdupd",
    "sync_ident",
    "sync_account",
];

// The first 26 fields are the common protocol-benchmark schema. The trailing
// fields retain the distribution data emitted by the historical benchmarks.
const OUTPUT_COLUMNS: [&str; 33] = [
    "scheme",
    "phase",
    "kind",
    "net_profile",
    "nsp",
    "tsp",
    "qsp",
    "unavailable",
    "delivery_bound_ns",
    "samples",
    "warmup",
    "client_ns",
    "provider_ns",
    "login_server_ns",
    "network_ns",
    "total_ns",
    "identification_stage_ns",
    "account_read_stage_ns",
    "prepare_stage_ns",
    "write_stage_ns",
    "terminal_stage_ns",
    "request_bytes",
    "response_bytes",
    "message_count",
    "acknowledgement_count",
    "result",
    "rng_in_timed",
    "min_ns",
    "p50_ns",
    "p95_ns",
    "max_ns",
    "mean_ns",
    "stddev_ns",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
    UpSpa,
    RoUpSpa,
    PasTaU,
    AugSso,
}

impl Scheme {
    const ALL: [Self; 4] = [Self::UpSpa, Self::RoUpSpa, Self::PasTaU, Self::AugSso];

    pub fn name(self) -> &'static str {
        match self {
            Self::UpSpa => "upspa",
            Self::RoUpSpa => "roupspa",
            Self::PasTaU => "pastau",
            Self::AugSso => "augsso",
        }
    }

    fn supported_kinds(self) -> &'static [&'static str] {
        match self {
            Self::UpSpa | Self::RoUpSpa => &MODERN_KINDS,
            Self::PasTaU | Self::AugSso => &HISTORICAL_KINDS,
        }
    }

    fn supported_ops(self) -> &'static [&'static str] {
        match self {
            Self::RoUpSpa => &ROUPSPA_OPS,
            Self::UpSpa | Self::PasTaU | Self::AugSso => &UPSPA_OPS,
        }
    }
}

#[derive(Clone, Debug)]
enum Offline {
    Max,
    None,
    Count(usize),
}

impl Offline {
    fn as_arg(&self) -> String {
        match self {
            Self::Max => "max".into(),
            Self::None => "none".into(),
            Self::Count(value) => value.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
struct Config {
    schemes: Vec<Scheme>,
    kinds: BTreeSet<String>,
    ops: BTreeSet<String>,
    nsp: Vec<usize>,
    tsp: Option<Vec<usize>>,
    tsp_pct: Option<Vec<u32>>,
    qsp: Option<Vec<usize>>,
    sample_size: usize,
    warmup_iters: usize,
    proc_warmup: usize,
    proc_samples: usize,
    net: String,
    lan_rtt_ms: f64,
    lan_jitter_ms: f64,
    lan_bw_mbps: f64,
    wan_rtt_ms: f64,
    wan_jitter_ms: f64,
    wan_bw_mbps: f64,
    overhead_bytes: usize,
    delivery_bound_ms: Option<f64>,
    offline: Offline,
    legacy_pwdupd: Option<String>,
    rng_in_timed: bool,
    out: PathBuf,
    dry_run: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schemes: vec![Scheme::UpSpa, Scheme::RoUpSpa],
            kinds: all_kinds(),
            ops: all_ops(),
            nsp: vec![20, 40, 60],
            tsp: None,
            tsp_pct: Some(vec![60]),
            qsp: None,
            sample_size: 200,
            warmup_iters: 50,
            proc_warmup: 200,
            proc_samples: 1000,
            net: "all".into(),
            lan_rtt_ms: 0.5,
            lan_jitter_ms: 0.05,
            lan_bw_mbps: 1000.0,
            wan_rtt_ms: 60.0,
            wan_jitter_ms: 5.0,
            wan_bw_mbps: 50.0,
            overhead_bytes: 64,
            delivery_bound_ms: None,
            offline: Offline::Max,
            legacy_pwdupd: None,
            rng_in_timed: false,
            out: PathBuf::from("results/upspa_roupspa_bench.dat"),
            dry_run: false,
        }
    }
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}

fn execute() -> Result<(), Box<dyn Error>> {
    let cfg = parse_args(std::env::args().skip(1).collect())?;
    validate(&cfg)?;
    if cfg.dry_run {
        print_plan(&cfg);
        return Ok(());
    }

    if let Some(parent) = cfg.out.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(&cfg.out)?;
    let mut output = BufWriter::new(file);
    writeln!(output, "{}", OUTPUT_COLUMNS.join(" "))?;

    let mut rows = 0usize;
    for &scheme in &cfg.schemes {
        if !has_work(scheme, &cfg) {
            continue;
        }
        let temporary = temporary_path(&cfg.out, scheme);
        eprintln!("running {}", scheme.name());
        if let Err(error) = run_scheme(scheme, &cfg, &temporary) {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        let merged = merge_rows(scheme, &temporary, &mut output);
        let cleanup = fs::remove_file(&temporary);
        rows += merged?;
        cleanup?;
    }

    output.flush()?;
    eprintln!("wrote {} rows to {}", rows, cfg.out.display());
    Ok(())
}

fn all_kinds() -> BTreeSet<String> {
    MODERN_KINDS
        .into_iter()
        .chain(HISTORICAL_KINDS)
        .map(str::to_owned)
        .collect()
}

fn all_ops() -> BTreeSet<String> {
    ROUPSPA_OPS.into_iter().map(str::to_owned).collect()
}

fn parse_args(args: Vec<String>) -> Result<Config, String> {
    let mut cfg = Config::default();
    let mut index = 0usize;
    while index < args.len() {
        let flag = &args[index];
        match flag.as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--scheme" | "--schemes" => {
                cfg.schemes = parse_schemes(value(&args, &mut index, flag)?)?;
            }
            "--kind" => cfg.kinds = parse_kinds(value(&args, &mut index, flag)?)?,
            "--ops" => cfg.ops = parse_ops(value(&args, &mut index, flag)?)?,
            "--nsp" => cfg.nsp = parse_list(value(&args, &mut index, flag)?, "nsp")?,
            "--tsp" => {
                cfg.tsp = Some(parse_list(value(&args, &mut index, flag)?, "tsp")?);
                cfg.tsp_pct = None;
            }
            "--tsp-pct" => {
                cfg.tsp_pct = Some(parse_list(value(&args, &mut index, flag)?, "tsp-pct")?);
                cfg.tsp = None;
            }
            "--qsp" => cfg.qsp = Some(parse_list(value(&args, &mut index, flag)?, "qsp")?),
            "--sample-size" | "--samples" => {
                cfg.sample_size = parse_value(value(&args, &mut index, flag)?, flag)?;
            }
            "--warmup-iters" | "--warmup" => {
                cfg.warmup_iters = parse_value(value(&args, &mut index, flag)?, flag)?;
            }
            "--proc-warmup" => {
                cfg.proc_warmup = parse_value(value(&args, &mut index, flag)?, flag)?;
            }
            "--proc-samples" => {
                cfg.proc_samples = parse_value(value(&args, &mut index, flag)?, flag)?;
            }
            "--net" => cfg.net = value(&args, &mut index, flag)?.to_ascii_lowercase(),
            "--lan-rtt-ms" => {
                cfg.lan_rtt_ms = parse_value(value(&args, &mut index, flag)?, flag)?;
            }
            "--lan-jitter-ms" => {
                cfg.lan_jitter_ms = parse_value(value(&args, &mut index, flag)?, flag)?;
            }
            "--lan-bw-mbps" => {
                cfg.lan_bw_mbps = parse_value(value(&args, &mut index, flag)?, flag)?;
            }
            "--wan-rtt-ms" => {
                cfg.wan_rtt_ms = parse_value(value(&args, &mut index, flag)?, flag)?;
            }
            "--wan-jitter-ms" => {
                cfg.wan_jitter_ms = parse_value(value(&args, &mut index, flag)?, flag)?;
            }
            "--wan-bw-mbps" => {
                cfg.wan_bw_mbps = parse_value(value(&args, &mut index, flag)?, flag)?;
            }
            "--overhead-bytes" => {
                cfg.overhead_bytes = parse_value(value(&args, &mut index, flag)?, flag)?;
            }
            "--delivery-bound-ms" => {
                cfg.delivery_bound_ms = Some(parse_value(value(&args, &mut index, flag)?, flag)?);
            }
            "--offline" | "--unavailable" => {
                cfg.offline = parse_offline(value(&args, &mut index, flag)?)?;
            }
            // Retained solely so old command lines still parse. This value is
            // deliberately never forwarded to UpSPA or RoUpSPA.
            "--pwdupd" => {
                cfg.legacy_pwdupd = Some(value(&args, &mut index, flag)?.to_ascii_lowercase());
            }
            "--pwdupd-v2" => cfg.legacy_pwdupd = Some("v2".into()),
            "--out" => cfg.out = PathBuf::from(value(&args, &mut index, flag)?),
            "--rng-in-timed" | "--rng" => cfg.rng_in_timed = true,
            "--dry-run" => cfg.dry_run = true,
            "--bench" => {}
            _ => return Err(format!("unknown argument '{flag}'; use --help")),
        }
        index += 1;
    }
    Ok(cfg)
}

fn value<'a>(args: &'a [String], index: &mut usize, flag: &str) -> Result<&'a str, String> {
    *index += 1;
    args.get(*index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_value<T: std::str::FromStr>(text: &str, name: &str) -> Result<T, String> {
    text.parse()
        .map_err(|_| format!("invalid value '{text}' for {name}"))
}

fn parse_list<T: std::str::FromStr>(text: &str, name: &str) -> Result<Vec<T>, String> {
    let values = text
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| parse_value(part.trim(), name))
        .collect::<Result<Vec<_>, _>>()?;
    if values.is_empty() {
        return Err(format!("{name} requires at least one value"));
    }
    Ok(values)
}

fn parse_schemes(text: &str) -> Result<Vec<Scheme>, String> {
    let mut schemes = Vec::new();
    for raw in text.split(',').map(str::trim).filter(|part| !part.is_empty()) {
        let name = raw.to_ascii_lowercase().replace('-', "_");
        if name == "all" {
            return Ok(Scheme::ALL.to_vec());
        }
        let scheme = match name.as_str() {
            "upspa" => Scheme::UpSpa,
            "roupspa" | "ro_upspa" | "upspa_quorum" | "upspa_abd" | "quorum" => Scheme::RoUpSpa,
            "pastau" | "pas_ta_u" | "pasta_u" => Scheme::PasTaU,
            "augsso" | "aug_sso" => Scheme::AugSso,
            _ => return Err(format!("unknown scheme '{raw}'")),
        };
        if !schemes.contains(&scheme) {
            schemes.push(scheme);
        }
    }
    if schemes.is_empty() {
        return Err("--scheme requires at least one value".into());
    }
    Ok(schemes)
}

fn parse_kinds(text: &str) -> Result<BTreeSet<String>, String> {
    let mut kinds = BTreeSet::new();
    for raw in text.split(',').map(str::trim).filter(|part| !part.is_empty()) {
        let normalized = raw.to_ascii_lowercase().replace('-', "_");
        if normalized == "all" {
            return Ok(all_kinds());
        }
        let kind = match normalized.as_str() {
            "loginserver" | "ls" => "login_server",
            value => value,
        };
        if !MODERN_KINDS.contains(&kind) && !HISTORICAL_KINDS.contains(&kind) {
            return Err(format!("unknown benchmark kind '{raw}'"));
        }
        kinds.insert(kind.to_owned());
    }
    if kinds.is_empty() {
        return Err("--kind requires at least one value".into());
    }
    Ok(kinds)
}

fn parse_ops(text: &str) -> Result<BTreeSet<String>, String> {
    let mut ops = BTreeSet::new();
    for raw in text.split(',').map(str::trim).filter(|part| !part.is_empty()) {
        let normalized = raw.to_ascii_lowercase().replace('-', "_");
        if normalized == "all" {
            return Ok(all_ops());
        }
        let op = match normalized.as_str() {
            "sync_identification" => "sync_ident",
            value => value,
        };
        if !ROUPSPA_OPS.contains(&op) {
            return Err(format!(
                "unknown operation '{raw}'; use setup,reg,auth,secupd,pwdupd,sync-ident,sync-account, or all"
            ));
        }
        ops.insert(op.to_owned());
    }
    if ops.is_empty() {
        return Err("--ops requires at least one value".into());
    }
    Ok(ops)
}

fn parse_offline(text: &str) -> Result<Offline, String> {
    match text.to_ascii_lowercase().as_str() {
        "max" => Ok(Offline::Max),
        "none" => Ok(Offline::None),
        value => value
            .parse::<usize>()
            .map(Offline::Count)
            .map_err(|_| "--offline must be max, none, or a nonnegative integer".into()),
    }
}

fn validate(cfg: &Config) -> Result<(), String> {
    if cfg.nsp.iter().any(|&value| value == 0) {
        return Err("all --nsp values must be positive".into());
    }
    if cfg.sample_size == 0 || cfg.proc_samples == 0 {
        return Err("--sample-size and --proc-samples must be positive".into());
    }
    if !matches!(cfg.net.as_str(), "lan" | "wan" | "all") {
        return Err("--net must be lan, wan, or all".into());
    }
    validate_network("LAN", cfg.lan_rtt_ms, cfg.lan_jitter_ms, cfg.lan_bw_mbps)?;
    validate_network("WAN", cfg.wan_rtt_ms, cfg.wan_jitter_ms, cfg.wan_bw_mbps)?;
    if let Some(bound) = cfg.delivery_bound_ms {
        if !bound.is_finite() || bound < 0.0 {
            return Err("--delivery-bound-ms must be finite and nonnegative".into());
        }
    }
    if let Some(mode) = &cfg.legacy_pwdupd {
        if !matches!(mode.as_str(), "1" | "2" | "v1" | "v2" | "both" | "all") {
            return Err("deprecated --pwdupd must be v1, v2, or both".into());
        }
    }

    let tuples = threshold_tuples(cfg)?;
    if cfg.schemes.contains(&Scheme::RoUpSpa) {
        for &(nsp, tsp, qsp) in &tuples {
            if qsp == nsp && (cfg.ops.contains("sync_ident") || cfg.ops.contains("sync_account")) {
                return Err(format!(
                    "RoUpSPA synchronization requires qsp < nsp so the stale recovering provider can obtain qsp valid donor responses (nsp={nsp}, tsp={tsp}, qsp={qsp})"
                ));
            }
            if let Offline::Count(count) = cfg.offline {
                for operation in ROUPSPA_OPS
                    .iter()
                    .filter(|operation| cfg.ops.contains(**operation))
                {
                    let Some(maximum) = roupspa_maximum_unavailable(operation, nsp, tsp, qsp) else {
                        // Setup always runs with all providers regardless of the
                        // requested offline profile.
                        continue;
                    };
                    if count > maximum {
                        return Err(format!(
                            "--offline {count} exceeds the admissible maximum {maximum} for operation={operation}, nsp={nsp}, tsp={tsp}, qsp={qsp}"
                        ));
                    }
                }
            }
        }
    }
    if !cfg.schemes.iter().any(|&scheme| has_work(scheme, cfg)) {
        return Err("the selected schemes, kinds, and operations produce no benchmark rows".into());
    }
    Ok(())
}

fn roupspa_maximum_unavailable(operation: &str, nsp: usize, tsp: usize, qsp: usize) -> Option<usize> {
    match operation {
        "setup" => None,
        "auth" => Some(nsp - tsp),
        "reg" | "secupd" | "pwdupd" | "sync_ident" | "sync_account" => Some(nsp - qsp),
        _ => unreachable!("validated RoUpSPA operation"),
    }
}

fn validate_network(name: &str, rtt: f64, jitter: f64, bandwidth: f64) -> Result<(), String> {
    if !rtt.is_finite() || rtt < 0.0 {
        return Err(format!("{name} RTT must be finite and nonnegative"));
    }
    if !jitter.is_finite() || jitter < 0.0 {
        return Err(format!("{name} jitter must be finite and nonnegative"));
    }
    if !bandwidth.is_finite() || bandwidth <= 0.0 {
        return Err(format!("{name} bandwidth must be finite and positive"));
    }
    Ok(())
}

fn threshold_pairs(cfg: &Config) -> Result<Vec<(usize, usize)>, String> {
    let mut pairs = Vec::new();
    for &nsp in &cfg.nsp {
        if let Some(values) = &cfg.tsp {
            for &tsp in values {
                validate_tsp(nsp, tsp)?;
                pairs.push((nsp, tsp));
            }
        } else {
            for &pct in cfg.tsp_pct.as_ref().expect("threshold mode") {
                if pct == 0 || pct > 100 {
                    return Err(format!("tsp percentage {pct} is outside 1..=100"));
                }
                let tsp = ((nsp as u128 * pct as u128 + 99) / 100) as usize;
                validate_tsp(nsp, tsp)?;
                pairs.push((nsp, tsp));
            }
        }
    }
    Ok(pairs)
}

fn validate_tsp(nsp: usize, tsp: usize) -> Result<(), String> {
    if tsp == 0 || tsp > nsp {
        return Err(format!(
            "tsp={tsp} is invalid for nsp={nsp}; require 1 <= tsp <= nsp"
        ));
    }
    Ok(())
}

fn minimum_qsp(nsp: usize, tsp: usize) -> usize {
    (((nsp as u128) + (tsp as u128) + 1) / 2) as usize
}

fn validate_quorum(nsp: usize, tsp: usize, qsp: usize) -> Result<(), String> {
    if qsp < tsp || qsp > nsp {
        return Err(format!(
            "qsp={qsp} is invalid for nsp={nsp}, tsp={tsp}; require tsp <= qsp <= nsp"
        ));
    }
    let lhs = 2 * qsp as u128;
    let rhs = nsp as u128 + tsp as u128 - 1;
    if lhs <= rhs {
        return Err(format!(
            "qsp={qsp} is invalid for nsp={nsp}, tsp={tsp}; require 2*qsp - nsp > tsp - 1"
        ));
    }
    Ok(())
}

fn threshold_tuples(cfg: &Config) -> Result<Vec<(usize, usize, usize)>, String> {
    let mut tuples = Vec::new();
    for (nsp, tsp) in threshold_pairs(cfg)? {
        if let Some(qsp_values) = &cfg.qsp {
            for &qsp in qsp_values {
                validate_quorum(nsp, tsp, qsp)?;
                tuples.push((nsp, tsp, qsp));
            }
        } else {
            let qsp = minimum_qsp(nsp, tsp);
            validate_quorum(nsp, tsp, qsp)?;
            tuples.push((nsp, tsp, qsp));
        }
    }
    Ok(tuples)
}

fn has_work(scheme: Scheme, cfg: &Config) -> bool {
    scheme
        .supported_kinds()
        .iter()
        .any(|kind| cfg.kinds.contains(*kind))
        && scheme.supported_ops().iter().any(|op| cfg.ops.contains(*op))
}

fn selected_values(selected: &BTreeSet<String>, supported: &[&str]) -> String {
    let values = supported
        .iter()
        .filter(|value| selected.contains(**value))
        .copied()
        .collect::<Vec<_>>();
    if values.len() == supported.len() {
        "all".into()
    } else {
        values.join(",")
    }
}

fn cli_spelling(values: &str) -> String {
    values.replace('_', "-")
}

fn append_grid_args(args: &mut Vec<String>, cfg: &Config) {
    args.extend(["--nsp".into(), join_numbers(&cfg.nsp)]);
    if let Some(tsp) = &cfg.tsp {
        args.extend(["--tsp".into(), join_numbers(tsp)]);
    } else {
        args.extend([
            "--tsp-pct".into(),
            join_numbers(cfg.tsp_pct.as_ref().expect("threshold mode")),
        ]);
    }
}

fn append_network_args(args: &mut Vec<String>, cfg: &Config) {
    args.extend([
        "--net".into(),
        cfg.net.clone(),
        "--lan-rtt-ms".into(),
        cfg.lan_rtt_ms.to_string(),
        "--lan-jitter-ms".into(),
        cfg.lan_jitter_ms.to_string(),
        "--lan-bw-mbps".into(),
        cfg.lan_bw_mbps.to_string(),
        "--wan-rtt-ms".into(),
        cfg.wan_rtt_ms.to_string(),
        "--wan-jitter-ms".into(),
        cfg.wan_jitter_ms.to_string(),
        "--wan-bw-mbps".into(),
        cfg.wan_bw_mbps.to_string(),
        "--overhead-bytes".into(),
        cfg.overhead_bytes.to_string(),
    ]);
}

fn modern_args(scheme: Scheme, cfg: &Config, out: &Path) -> Vec<String> {
    let kinds = selected_values(&cfg.kinds, scheme.supported_kinds());
    let ops = selected_values(&cfg.ops, scheme.supported_ops());
    let mut args = vec![
        "--kind".into(),
        cli_spelling(&kinds),
        "--ops".into(),
        cli_spelling(&ops),
        "--sample-size".into(),
        cfg.sample_size.to_string(),
        "--warmup-iters".into(),
        cfg.warmup_iters.to_string(),
        "--out".into(),
        out.to_string_lossy().into_owned(),
    ];
    append_grid_args(&mut args, cfg);
    append_network_args(&mut args, cfg);
    if let Some(bound) = cfg.delivery_bound_ms {
        args.extend(["--delivery-bound-ms".into(), bound.to_string()]);
    }
    if scheme == Scheme::UpSpa {
        args.extend(["--scheme".into(), "upspa".into()]);
    } else {
        if let Some(qsp) = &cfg.qsp {
            args.extend(["--qsp".into(), join_numbers(qsp)]);
        }
        args.extend(["--offline".into(), cfg.offline.as_arg()]);
    }
    if cfg.rng_in_timed {
        args.push("--rng-in-timed".into());
    }
    args
}

fn historical_args(scheme: Scheme, cfg: &Config, out: &Path) -> Vec<String> {
    let kinds = selected_values(&cfg.kinds, scheme.supported_kinds());
    let mut args = vec![
        match scheme {
            Scheme::PasTaU => "bench_pastau".into(),
            Scheme::AugSso => "bench_augsso".into(),
            _ => unreachable!("historical_args called for a modern scheme"),
        },
        "--kind".into(),
        cli_spelling(&kinds),
        "--sample-size".into(),
        cfg.sample_size.to_string(),
        "--warmup-iters".into(),
        cfg.warmup_iters.to_string(),
        "--proc-warmup".into(),
        cfg.proc_warmup.to_string(),
        "--proc-samples".into(),
        cfg.proc_samples.to_string(),
        "--out".into(),
        out.to_string_lossy().into_owned(),
    ];
    append_grid_args(&mut args, cfg);
    append_network_args(&mut args, cfg);
    if cfg.rng_in_timed {
        args.push("--rng-in-timed".into());
    }
    args
}

fn run_scheme(scheme: Scheme, cfg: &Config, out: &Path) -> Result<(), Box<dyn Error>> {
    match scheme {
        Scheme::UpSpa => upspa_bench::benchmark::run(modern_args(scheme, cfg, out))?,
        Scheme::RoUpSpa => upspa_quorum_bench::benchmark::run(modern_args(scheme, cfg, out))?,
        Scheme::PasTaU => pastau_bench::benchmark::run(historical_args(scheme, cfg, out))?,
        Scheme::AugSso => augsso_bench::benchmark::run(historical_args(scheme, cfg, out))?,
    }
    Ok(())
}

fn join_numbers<T: ToString>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn temporary_path(output: &Path, scheme: Scheme) -> PathBuf {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let stem = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("benchmark");
    parent.join(format!(".{stem}.{}.{}.tmp", scheme.name(), std::process::id()))
}

fn merge_rows(scheme: Scheme, path: &Path, output: &mut BufWriter<File>) -> Result<usize, Box<dyn Error>> {
    let contents = fs::read_to_string(path)?;
    let mut lines = contents.lines();
    let header = lines
        .next()
        .ok_or_else(|| format!("benchmark output {} is empty", path.display()))?;
    let columns = header.split_whitespace().collect::<Vec<_>>();
    if columns.is_empty() {
        return Err(format!("benchmark output {} has an empty header", path.display()).into());
    }
    let unique = columns.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != columns.len() {
        return Err(format!("benchmark output {} has duplicate columns", path.display()).into());
    }
    for required in ["scheme", "kind", "nsp", "tsp"] {
        if !unique.contains(required) {
            return Err(format!(
                "benchmark output {} is missing required column '{required}'",
                path.display()
            )
            .into());
        }
    }
    if !unique.contains("phase") && !unique.contains("op") {
        return Err(format!(
            "benchmark output {} is missing required column 'phase' (or legacy 'op')",
            path.display()
        )
        .into());
    }

    let mut rows = 0usize;
    for (offset, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let values = line.split_whitespace().collect::<Vec<_>>();
        if values.len() != columns.len() {
            return Err(format!(
                "invalid row at {}:{}: header has {} columns but row has {}",
                path.display(),
                offset + 2,
                columns.len(),
                values.len()
            )
            .into());
        }
        let fields = columns
            .iter()
            .zip(values)
            .map(|(&column, value)| (column, value))
            .collect::<BTreeMap<_, _>>();
        writeln!(output, "{}", canonical_row(scheme, &fields).join(" "))?;
        rows += 1;
    }
    Ok(rows)
}

fn canonical_row(scheme: Scheme, fields: &BTreeMap<&str, &str>) -> Vec<String> {
    OUTPUT_COLUMNS
        .iter()
        .map(|&column| {
            let value = match column {
                "scheme" => Some(scheme.name()),
                "phase" => fields.get("phase").or_else(|| fields.get("op")).copied(),
                "net_profile" => fields.get("net_profile").copied().or_else(|| {
                    fields
                        .get("phase")
                        .or_else(|| fields.get("op"))
                        .map(|op| network_profile(op))
                }),
                "login_server_ns" => fields
                    .get("login_server_ns")
                    .or_else(|| fields.get("ls_ns"))
                    .copied(),
                "total_ns" => fields.get("total_ns").or_else(|| fields.get("mean_ns")).copied(),
                "acknowledgement_count" => fields
                    .get("acknowledgement_count")
                    .or_else(|| fields.get("acknowledgment_count"))
                    .copied(),
                "result" => Some(fields.get("result").copied().unwrap_or("ok")),
                _ => fields.get(column).copied(),
            };
            value.unwrap_or_else(|| default_column_value(column)).to_owned()
        })
        .collect()
}

fn default_column_value(column: &str) -> &'static str {
    match column {
        "phase" | "kind" => "unknown",
        "net_profile" => "none",
        "result" => "ok",
        _ => "0",
    }
}

fn network_profile(op: &str) -> &'static str {
    if op.split('_').any(|part| part == "lan") {
        "lan"
    } else if op.split('_').any(|part| part == "wan") {
        "wan"
    } else {
        "none"
    }
}

fn print_plan(cfg: &Config) {
    println!(
        "schemes={}",
        cfg.schemes
            .iter()
            .map(|scheme| scheme.name())
            .collect::<Vec<_>>()
            .join(",")
    );
    println!(
        "kinds={}",
        cfg.kinds.iter().cloned().collect::<Vec<_>>().join(",")
    );
    println!("ops={}", cfg.ops.iter().cloned().collect::<Vec<_>>().join(","));
    println!("nsp={}", join_numbers(&cfg.nsp));
    if let Some(tsp) = &cfg.tsp {
        println!("tsp={}", join_numbers(tsp));
    } else {
        println!(
            "tsp_pct={}",
            join_numbers(cfg.tsp_pct.as_ref().expect("threshold mode"))
        );
    }
    if let Some(qsp) = &cfg.qsp {
        println!("qsp={}", join_numbers(qsp));
    } else {
        println!("qsp=minimum-strict-intersection");
    }
    println!(
        "tuples={}",
        threshold_tuples(cfg)
            .expect("validated threshold tuples")
            .iter()
            .map(|(nsp, tsp, qsp)| format!("{nsp}/{tsp}/{qsp}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("samples={} warmup={}", cfg.sample_size, cfg.warmup_iters);
    println!(
        "proc_samples={} proc_warmup={}",
        cfg.proc_samples, cfg.proc_warmup
    );
    println!(
        "net={} offline={} delivery_bound_ms={} out={}",
        cfg.net,
        cfg.offline.as_arg(),
        cfg.delivery_bound_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "derived".into()),
        cfg.out.display()
    );
    if let Some(mode) = &cfg.legacy_pwdupd {
        println!("deprecated_pwdupd={mode} (ignored by UpSPA and RoUpSPA)");
    }
}

fn print_help() {
    println!(
        r#"Unified UpSPA and RoUpSPA protocol benchmark

USAGE
  cargo run --release --bin bench_unified -- [OPTIONS]

SELECTION
  --scheme upspa,roupspa|all
      RoUpSPA aliases: upspa-quorum, upspa_quorum, upspa_abd, quorum
      Historical compatibility schemes: pastau, augsso
  --kind all|client|provider|login-server|full-no-net|net-only|full-net
      Historical compatibility kinds: proto, prim, sp, net, full
  --ops all|setup,reg,auth,secupd,pwdupd,sync-ident,sync-account
  --pwdupd v1|v2|both
      Deprecated and ignored by UpSPA/RoUpSPA; each has one fixed protocol.

GRID AND TIMING
  --nsp N[,N...]
  --tsp T[,T...] | --tsp-pct P[,P...]
  --qsp Q[,Q...]
      Optional for RoUpSPA. Every tuple must satisfy tsp <= qsp <= nsp and
      2*qsp - nsp > tsp - 1. If omitted, the minimum valid qsp is used.
  --sample-size N
  --warmup-iters N
  --proc-warmup N       Historical schemes only
  --proc-samples N      Historical schemes only
  --rng-in-timed

NETWORK
  --net lan|wan|all
  --lan-rtt-ms X
  --lan-jitter-ms X
  --lan-bw-mbps X
  --wan-rtt-ms X
  --wan-jitter-ms X
  --wan-bw-mbps X
  --overhead-bytes N
  --delivery-bound-ms X
      Optional one-way terminal-delivery bound; derived per profile if omitted.

ROUPSPA AVAILABILITY
  --offline max|none|N

OUTPUT
  --out PATH
  --dry-run

DEFAULTS
  schemes=upspa,roupspa, kinds=all, ops=all
  nsp=20,40,60, tsp-pct=60, qsp=minimum valid strict-intersection quorum
  sample-size=200, warmup-iters=50
  LAN=0.5/0.05 ms at 1000 Mbps, WAN=60/5 ms at 50 Mbps
  overhead-bytes=64, delivery-bound-ms=derived, offline=max
"#
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn revised_default_runs_only_upspa_and_roupspa() {
        let cfg = Config::default();
        assert_eq!(cfg.schemes, vec![Scheme::UpSpa, Scheme::RoUpSpa]);
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn roupspa_public_name_and_aliases_are_stable() {
        assert_eq!(Scheme::RoUpSpa.name(), "roupspa");
        for alias in ["roupspa", "upspa-quorum", "upspa_quorum", "upspa_abd", "quorum"] {
            assert_eq!(parse_schemes(alias).unwrap(), vec![Scheme::RoUpSpa]);
        }
    }

    #[test]
    fn explicit_all_retains_historical_schemes() {
        assert_eq!(parse_schemes("all").unwrap(), Scheme::ALL);
    }

    #[test]
    fn default_quorum_is_the_minimum_strict_intersection_quorum() {
        let cfg = parse_args(args(&["--nsp", "7", "--tsp", "2"])).unwrap();
        assert_eq!(threshold_tuples(&cfg).unwrap(), vec![(7, 2, 5)]);
        assert!(validate_quorum(7, 2, 5).is_ok());
        assert!(validate_quorum(7, 2, 4).is_err());
    }

    #[test]
    fn every_explicit_quorum_tuple_is_validated() {
        let cfg = parse_args(args(&["--nsp", "7", "--tsp", "2", "--qsp", "5,4"])).unwrap();
        let error = validate(&cfg).unwrap_err();
        assert!(error.contains("2*qsp - nsp > tsp - 1"));
    }

    #[test]
    fn explicit_offline_count_is_bounded_by_selected_quorum() {
        let cfg = parse_args(args(&[
            "--scheme",
            "roupspa",
            "--nsp",
            "7",
            "--tsp",
            "2",
            "--qsp",
            "6",
            "--offline",
            "2",
        ]))
        .unwrap();
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn authentication_uses_threshold_availability_not_quorum_availability() {
        let auth = parse_args(args(&[
            "--scheme",
            "roupspa",
            "--ops",
            "auth",
            "--nsp",
            "7",
            "--tsp",
            "2",
            "--qsp",
            "5",
            "--offline",
            "5",
        ]))
        .unwrap();
        assert!(validate(&auth).is_ok());

        let quorum_write = parse_args(args(&[
            "--scheme",
            "roupspa",
            "--ops",
            "reg",
            "--nsp",
            "7",
            "--tsp",
            "2",
            "--qsp",
            "5",
            "--offline",
            "5",
        ]))
        .unwrap();
        assert!(validate(&quorum_write).is_err());
    }

    #[test]
    fn synchronization_rejects_a_quorum_with_no_external_donor_set() {
        let cfg = parse_args(args(&[
            "--scheme",
            "roupspa",
            "--ops",
            "sync-ident",
            "--nsp",
            "3",
            "--tsp",
            "2",
            "--qsp",
            "3",
        ]))
        .unwrap();
        assert!(validate(&cfg).unwrap_err().contains("qsp < nsp"));
    }

    #[test]
    fn all_required_operations_and_hyphenated_sync_aliases_parse() {
        let cfg = parse_args(args(&[
            "--ops",
            "setup,reg,auth,secupd,pwdupd,sync-ident,sync-account",
        ]))
        .unwrap();
        assert_eq!(cfg.ops, all_ops());
    }

    #[test]
    fn legacy_password_flag_cannot_change_modern_arguments() {
        let v1 = parse_args(args(&["--pwdupd", "v1"])).unwrap();
        let v2 = parse_args(args(&["--pwdupd", "v2"])).unwrap();
        let out = Path::new("ignored.dat");
        let v1_args = modern_args(Scheme::UpSpa, &v1, out);
        let v2_args = modern_args(Scheme::UpSpa, &v2, out);
        assert_eq!(v1_args, v2_args);
        assert!(!v1_args.iter().any(|arg| arg == "--pwdupd"));
    }

    #[test]
    fn roupspa_receives_explicit_quorum_and_delivery_bound() {
        let cfg = parse_args(args(&[
            "--nsp",
            "7",
            "--tsp",
            "2",
            "--qsp",
            "5",
            "--delivery-bound-ms",
            "3.5",
        ]))
        .unwrap();
        let forwarded = modern_args(Scheme::RoUpSpa, &cfg, Path::new("ignored.dat"));
        assert!(forwarded.windows(2).any(|pair| pair == ["--qsp", "5"]));
        assert!(forwarded
            .windows(2)
            .any(|pair| pair == ["--delivery-bound-ms", "3.5"]));
    }

    #[test]
    fn merge_uses_column_names_and_forces_public_scheme_name() {
        let fields = BTreeMap::from([
            ("scheme", "upspa_abd"),
            ("kind", "full_no_net"),
            ("op", "reg"),
            ("nsp", "7"),
            ("tsp", "2"),
            ("qsp", "5"),
            ("samples", "3"),
            ("warmup", "1"),
            ("mean_ns", "42.5"),
        ]);
        let row = canonical_row(Scheme::RoUpSpa, &fields);
        let index = |name| OUTPUT_COLUMNS.iter().position(|column| *column == name).unwrap();
        assert_eq!(row[index("scheme")], "roupspa");
        assert_eq!(row[index("phase")], "reg");
        assert_eq!(row[index("qsp")], "5");
        assert_eq!(row[index("total_ns")], "42.5");
    }

    #[test]
    fn network_profile_is_derived_for_historical_rows() {
        assert_eq!(network_profile("lan_auth_total"), "lan");
        assert_eq!(network_profile("auth_wan"), "wan");
        assert_eq!(network_profile("auth"), "none");
    }
}
