use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

const BASELINE_KINDS: [&str; 5] = ["proto", "prim", "sp", "net", "full"];
const QUORUM_KINDS: [&str; 3] = ["full_no_net", "full_net", "quorum_overhead"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scheme {
    UpSpa,
    PasTaU,
    AugSso,
    UpSpaQuorum,
}

impl Scheme {
    fn name(self) -> &'static str {
        match self {
            Self::UpSpa => "upspa",
            Self::PasTaU => "pastau",
            Self::AugSso => "augsso",
            Self::UpSpaQuorum => "upspa_quorum",
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
    ops: String,
    nsp: Vec<usize>,
    tsp: Option<Vec<usize>>,
    tsp_pct: Option<Vec<u32>>,
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
    offline: Offline,
    pwdupd: String,
    rng_in_timed: bool,
    out: PathBuf,
    dry_run: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schemes: vec![Scheme::UpSpa, Scheme::PasTaU, Scheme::AugSso, Scheme::UpSpaQuorum],
            kinds: BASELINE_KINDS
                .into_iter()
                .chain(QUORUM_KINDS)
                .map(str::to_owned)
                .collect(),
            ops: "all".into(),
            nsp: vec![20, 40, 60],
            tsp: None,
            tsp_pct: Some(vec![60]),
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
            offline: Offline::Max,
            pwdupd: "v2".into(),
            rng_in_timed: false,
            out: PathBuf::from("results/unified_bench.dat"),
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
    writeln!(
        output,
        "scheme kind op net_profile rng_in_timed nsp tsp qsp unavailable samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns"
    )?;

    let mut rows = 0usize;
    for scheme in &cfg.schemes {
        if !has_work(*scheme, &cfg.kinds) {
            continue;
        }
        let temporary = temporary_path(&cfg.out, *scheme);
        eprintln!("running {}", scheme.name());
        let result = run_scheme(*scheme, &cfg, &temporary);
        if let Err(error) = result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        rows += merge_rows(*scheme, &temporary, &mut output)?;
        fs::remove_file(&temporary)?;
    }

    output.flush()?;
    eprintln!("wrote {} rows to {}", rows, cfg.out.display());
    Ok(())
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
            "--kind" => {
                cfg.kinds = parse_kinds(value(&args, &mut index, flag)?)?;
            }
            "--ops" => cfg.ops = value(&args, &mut index, flag)?.to_ascii_lowercase(),
            "--nsp" => cfg.nsp = parse_list(value(&args, &mut index, flag)?, "nsp")?,
            "--tsp" => {
                cfg.tsp = Some(parse_list(value(&args, &mut index, flag)?, "tsp")?);
                cfg.tsp_pct = None;
            }
            "--tsp-pct" => {
                cfg.tsp_pct = Some(parse_list(value(&args, &mut index, flag)?, "tsp-pct")?);
                cfg.tsp = None;
            }
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
            "--offline" | "--unavailable" => {
                cfg.offline = parse_offline(value(&args, &mut index, flag)?)?;
            }
            "--pwdupd" => cfg.pwdupd = value(&args, &mut index, flag)?.to_ascii_lowercase(),
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
    for name in text.split(',').map(|part| part.trim().to_ascii_lowercase()) {
        if name == "all" {
            return Ok(Config::default().schemes);
        }
        let scheme = match name.replace('-', "_").as_str() {
            "upspa" => Scheme::UpSpa,
            "pastau" | "pas_ta_u" => Scheme::PasTaU,
            "augsso" => Scheme::AugSso,
            "quorum" | "upspa_quorum" | "upspa_abd" => Scheme::UpSpaQuorum,
            _ => return Err(format!("unknown scheme '{name}'")),
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
    let all: BTreeSet<String> = BASELINE_KINDS
        .into_iter()
        .chain(QUORUM_KINDS)
        .map(str::to_owned)
        .collect();
    let mut kinds = BTreeSet::new();
    for raw in text.split(',').map(str::trim).filter(|part| !part.is_empty()) {
        let kind = raw.to_ascii_lowercase().replace('-', "_");
        if kind == "all" {
            return Ok(all);
        }
        let kind = if kind == "quorum" {
            "quorum_overhead".into()
        } else {
            kind
        };
        if !all.contains(&kind) {
            return Err(format!("unknown benchmark kind '{raw}'"));
        }
        kinds.insert(kind);
    }
    if kinds.is_empty() {
        return Err("--kind requires at least one value".into());
    }
    Ok(kinds)
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
    if !matches!(cfg.pwdupd.as_str(), "1" | "2" | "v1" | "v2" | "both" | "all") {
        return Err("--pwdupd must be v1, v2, or both".into());
    }
    let ops: BTreeSet<&str> = cfg.ops.split(',').map(str::trim).collect();
    if !ops.contains("all") && ops.iter().any(|op| !matches!(*op, "reg" | "secupd" | "pwdupd")) {
        return Err("--ops must contain only reg, secupd, pwdupd, or all".into());
    }
    let thresholds = thresholds(cfg)?;
    if cfg.schemes.contains(&Scheme::UpSpaQuorum) {
        if let Offline::Count(count) = cfg.offline {
            for (nsp, tsp) in thresholds {
                let qsp = (nsp + tsp + 1) / 2;
                let maximum = nsp - qsp;
                if count > maximum {
                    return Err(format!(
                        "--offline {count} exceeds the admissible maximum {maximum} for nsp={nsp}, tsp={tsp}"
                    ));
                }
            }
        }
    }
    if !cfg.schemes.iter().any(|scheme| has_work(*scheme, &cfg.kinds)) {
        return Err("the selected schemes and kinds produce no benchmark rows".into());
    }
    Ok(())
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

fn thresholds(cfg: &Config) -> Result<Vec<(usize, usize)>, String> {
    let mut pairs = Vec::new();
    for &nsp in &cfg.nsp {
        if let Some(values) = &cfg.tsp {
            for &tsp in values {
                if tsp == 0 || tsp > nsp {
                    return Err(format!(
                        "tsp={tsp} is invalid for nsp={nsp}; require 1 <= tsp <= nsp"
                    ));
                }
                pairs.push((nsp, tsp));
            }
        } else {
            for &pct in cfg.tsp_pct.as_ref().expect("threshold mode") {
                if pct == 0 || pct > 100 {
                    return Err(format!("tsp percentage {pct} is outside 1..=100"));
                }
                pairs.push((nsp, ((nsp as u128 * pct as u128 + 99) / 100) as usize));
            }
        }
    }
    Ok(pairs)
}

fn has_work(scheme: Scheme, kinds: &BTreeSet<String>) -> bool {
    let supported = if scheme == Scheme::UpSpaQuorum {
        &QUORUM_KINDS[..]
    } else {
        &BASELINE_KINDS[..]
    };
    supported.iter().any(|kind| kinds.contains(*kind))
}

fn selected_kinds(kinds: &BTreeSet<String>, supported: &[&str]) -> String {
    let selected = supported
        .iter()
        .filter(|kind| kinds.contains(**kind))
        .copied()
        .collect::<Vec<_>>();
    if selected.len() == supported.len() {
        "all".into()
    } else {
        selected.join(",")
    }
}

fn common_args(cfg: &Config, out: &Path, kinds: &str) -> Vec<String> {
    let mut args = vec![
        "--kind".into(),
        kinds.replace('_', "-"),
        "--net".into(),
        cfg.net.clone(),
        "--nsp".into(),
        join_numbers(&cfg.nsp),
        "--sample-size".into(),
        cfg.sample_size.to_string(),
        "--warmup-iters".into(),
        cfg.warmup_iters.to_string(),
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
        "--out".into(),
        out.to_string_lossy().into_owned(),
    ];
    if let Some(tsp) = &cfg.tsp {
        args.extend(["--tsp".into(), join_numbers(tsp)]);
    } else {
        args.extend([
            "--tsp-pct".into(),
            join_numbers(cfg.tsp_pct.as_ref().expect("threshold mode")),
        ]);
    }
    args
}

fn run_scheme(scheme: Scheme, cfg: &Config, out: &Path) -> Result<(), Box<dyn Error>> {
    match scheme {
        Scheme::UpSpa => {
            let kinds = selected_kinds(&cfg.kinds, &BASELINE_KINDS);
            let mut args = common_args(cfg, out, &kinds);
            args.extend([
                "--scheme".into(),
                "upspa".into(),
                "--pwdupd".into(),
                cfg.pwdupd.clone(),
                "--proc-warmup".into(),
                cfg.proc_warmup.to_string(),
                "--proc-samples".into(),
                cfg.proc_samples.to_string(),
            ]);
            if cfg.rng_in_timed {
                args.push("--rng-in-timed".into());
            }
            upspa_bench::benchmark::run(args)?;
        }
        Scheme::PasTaU => {
            let kinds = selected_kinds(&cfg.kinds, &BASELINE_KINDS);
            let mut args = vec!["bench_pastau".into()];
            args.extend(common_args(cfg, out, &kinds));
            args.extend([
                "--proc-warmup".into(),
                cfg.proc_warmup.to_string(),
                "--proc-samples".into(),
                cfg.proc_samples.to_string(),
            ]);
            if cfg.rng_in_timed {
                args.push("--rng-in-timed".into());
            }
            pastau_bench::benchmark::run(args)?;
        }
        Scheme::AugSso => {
            let kinds = selected_kinds(&cfg.kinds, &BASELINE_KINDS);
            let mut args = vec!["bench_augsso".into()];
            args.extend(common_args(cfg, out, &kinds));
            args.extend([
                "--proc-warmup".into(),
                cfg.proc_warmup.to_string(),
                "--proc-samples".into(),
                cfg.proc_samples.to_string(),
            ]);
            if cfg.rng_in_timed {
                args.push("--rng-in-timed".into());
            }
            augsso_bench::benchmark::run(args)?;
        }
        Scheme::UpSpaQuorum => {
            let kinds = selected_kinds(&cfg.kinds, &QUORUM_KINDS);
            let mut args = common_args(cfg, out, &kinds);
            args.extend([
                "--ops".into(),
                cfg.ops.clone(),
                "--offline".into(),
                cfg.offline.as_arg(),
            ]);
            upspa_quorum_bench::benchmark::run(args)?;
        }
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
    let mut rows = 0usize;
    for (line_number, line) in contents.lines().enumerate().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if scheme == Scheme::UpSpaQuorum {
            if fields.len() != 16 {
                return Err(format!("invalid quorum row at {}:{}", path.display(), line_number + 1).into());
            }
            let row = [
                "upspa_quorum",
                fields[1],
                fields[2],
                fields[3],
                "0",
                fields[4],
                fields[5],
                fields[6],
                fields[7],
                fields[8],
                fields[9],
                fields[10],
                fields[11],
                fields[12],
                fields[13],
                fields[14],
                fields[15],
            ];
            writeln!(output, "{}", row.join(" "))?;
        } else {
            if fields.len() != 14 {
                return Err(format!("invalid baseline row at {}:{}", path.display(), line_number + 1).into());
            }
            let profile = network_profile(fields[2]);
            let row = [
                fields[0], fields[1], fields[2], profile, fields[3], fields[4], fields[5], "0", "0",
                fields[6], fields[7], fields[8], fields[9], fields[10], fields[11], fields[12], fields[13],
            ];
            writeln!(output, "{}", row.join(" "))?;
        }
        rows += 1;
    }
    Ok(rows)
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
    println!("nsp={}", join_numbers(&cfg.nsp));
    if let Some(tsp) = &cfg.tsp {
        println!("tsp={}", join_numbers(tsp));
    } else {
        println!(
            "tsp_pct={}",
            join_numbers(cfg.tsp_pct.as_ref().expect("threshold mode"))
        );
    }
    println!("samples={} warmup={}", cfg.sample_size, cfg.warmup_iters);
    println!(
        "proc_samples={} proc_warmup={}",
        cfg.proc_samples, cfg.proc_warmup
    );
    println!(
        "net={} offline={} out={}",
        cfg.net,
        cfg.offline.as_arg(),
        cfg.out.display()
    );
}

fn print_help() {
    println!(
        r#"Unified UpSPA paper benchmark

USAGE
  cargo run --release --bin bench_unified -- [OPTIONS]

SELECTION
  --scheme all|upspa|pastau|augsso|upspa-quorum
  --kind all|proto|prim|sp|net|full|full-no-net|full-net|quorum-overhead
  --ops all|reg,secupd,pwdupd
  --pwdupd v1|v2|both

GRID AND TIMING
  --nsp N[,N...]
  --tsp T[,T...] | --tsp-pct P[,P...]
  --sample-size N
  --warmup-iters N
  --proc-warmup N
  --proc-samples N
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

QUORUM
  --offline max|none|N

OUTPUT
  --out PATH
  --dry-run

DEFAULTS
  schemes=all, kinds=all, nsp=20,40,60, tsp-pct=60
  sample-size=200, warmup-iters=50, proc-warmup=200, proc-samples=1000
  LAN=0.5/0.05 ms at 1000 Mbps, WAN=60/5 ms at 50 Mbps
  overhead-bytes=64, offline=max, pwdupd=v2
"#
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_grid_is_valid() {
        let cfg = parse_args(vec![
            "--nsp".into(),
            "20".into(),
            "--tsp".into(),
            "11".into(),
            "--offline".into(),
            "max".into(),
        ])
        .unwrap();
        assert!(validate(&cfg).is_ok());
        assert_eq!(thresholds(&cfg).unwrap(), vec![(20, 11)]);
    }

    #[test]
    fn invalid_absolute_threshold_is_rejected() {
        let cfg = parse_args(vec!["--nsp".into(), "5".into(), "--tsp".into(), "6".into()]).unwrap();
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn explicit_offline_count_is_bounded_by_quorum() {
        let cfg = parse_args(vec![
            "--scheme".into(),
            "upspa-quorum".into(),
            "--nsp".into(),
            "20".into(),
            "--tsp".into(),
            "11".into(),
            "--offline".into(),
            "5".into(),
        ])
        .unwrap();
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn network_profile_is_derived_from_operation_name() {
        assert_eq!(network_profile("lan_auth_total"), "lan");
        assert_eq!(network_profile("auth_wan"), "wan");
        assert_eq!(network_profile("auth"), "none");
    }
}
