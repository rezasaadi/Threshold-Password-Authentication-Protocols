use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

use crate::protocols::{
    DeterministicTestClock, MessageEvent, PhaseKind, ProtocolStage, ProtocolTrace, UpSpaSystem, WaitPolicy,
};

const HEADER: &str = "scheme phase kind net_profile nsp tsp qsp unavailable delivery_bound_ns samples warmup client_ns provider_ns login_server_ns network_ns total_ns identification_stage_ns account_read_stage_ns prepare_stage_ns write_stage_ns terminal_stage_ns request_bytes response_bytes message_count acknowledgement_count result rng_in_timed min_ns p50_ns p95_ns max_ns mean_ns stddev_ns";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Setup,
    Registration,
    Authentication,
    SecretUpdate,
    PasswordUpdate,
}

impl Operation {
    const ALL: [Self; 5] = [
        Self::Setup,
        Self::Registration,
        Self::Authentication,
        Self::SecretUpdate,
        Self::PasswordUpdate,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Registration => "reg",
            Self::Authentication => "auth",
            Self::SecretUpdate => "secupd",
            Self::PasswordUpdate => "pwdupd",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Client,
    Provider,
    LoginServer,
    FullNoNet,
    NetOnly,
    FullNet,
}

impl Kind {
    const ALL: [Self; 6] = [
        Self::Client,
        Self::Provider,
        Self::LoginServer,
        Self::FullNoNet,
        Self::NetOnly,
        Self::FullNet,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Provider => "provider",
            Self::LoginServer => "login_server",
            Self::FullNoNet => "full_no_net",
            Self::NetOnly => "net_only",
            Self::FullNet => "full_net",
        }
    }

    fn uses_network(self) -> bool {
        matches!(self, Self::NetOnly | Self::FullNet)
    }
}

#[derive(Clone, Copy, Debug)]
struct NetProfile {
    name: &'static str,
    one_way_ns: u64,
    jitter_ns: u64,
    bandwidth_bps: u64,
    overhead_bytes: usize,
}

#[derive(Clone, Debug)]
struct Config {
    scheme_selected: bool,
    kinds: Vec<Kind>,
    operations: Vec<Operation>,
    nsp: Vec<usize>,
    tsp: Option<Vec<usize>>,
    tsp_pct: Vec<u32>,
    samples: usize,
    warmup: usize,
    output: String,
    rng_in_timed: bool,
    profiles: Vec<NetProfile>,
    explicit_delivery_bound_ns: Option<u64>,
}

#[derive(Clone, Debug)]
struct ProcessingSample {
    processing_ns: u64,
    client_ns: u64,
    provider_ns: u64,
    login_server_ns: u64,
    trace: ProtocolTrace,
}

#[derive(Clone, Debug, Default)]
struct NetworkCost {
    total_ns: u64,
    identification_ns: u64,
    account_read_ns: u64,
    prepare_ns: u64,
    write_ns: u64,
    terminal_ns: u64,
}

#[derive(Clone, Debug)]
struct Sample {
    client_ns: u64,
    provider_ns: u64,
    login_server_ns: u64,
    network: NetworkCost,
    total_ns: u64,
}

#[derive(Clone, Debug)]
struct Summary {
    client_ns: u64,
    provider_ns: u64,
    login_server_ns: u64,
    network_ns: u64,
    total_ns: u64,
    identification_stage_ns: u64,
    account_read_stage_ns: u64,
    prepare_stage_ns: u64,
    write_stage_ns: u64,
    terminal_stage_ns: u64,
    min_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    max_ns: u64,
    mean_ns: f64,
    stddev_ns: f64,
}

pub fn run(args: Vec<String>) -> io::Result<()> {
    let config = parse_args(args).map_err(invalid_input)?;
    let file = File::create(&config.output)?;
    let mut output = BufWriter::new(file);
    writeln!(output, "{HEADER}")?;
    if !config.scheme_selected {
        return output.flush();
    }

    for &nsp in &config.nsp {
        let thresholds = thresholds_for(&config, nsp)?;
        for tsp in thresholds {
            for &operation in &config.operations {
                for &kind in &config.kinds {
                    if kind.uses_network() {
                        for &profile in &config.profiles {
                            write_benchmark_row(
                                &mut output,
                                &config,
                                operation,
                                kind,
                                nsp,
                                tsp,
                                Some(profile),
                            )?;
                        }
                    } else {
                        write_benchmark_row(&mut output, &config, operation, kind, nsp, tsp, None)?;
                    }
                }
            }
        }
    }
    output.flush()
}

fn write_benchmark_row(
    output: &mut BufWriter<File>,
    config: &Config,
    operation: Operation,
    kind: Kind,
    nsp: usize,
    tsp: usize,
    profile: Option<NetProfile>,
) -> io::Result<()> {
    for iteration in 0..config.warmup {
        let processing =
            execute_processing_sample(operation, nsp, tsp, iteration as u64).map_err(invalid_input)?;
        let delivery_bound =
            delivery_bound_for(config.explicit_delivery_bound_ns, profile, &processing.trace);
        let _ = compose_sample(
            kind,
            processing,
            profile,
            delivery_bound,
            seed_u64(operation, nsp, tsp, iteration as u64, b"warmup"),
        );
    }

    let mut samples = Vec::with_capacity(config.samples);
    let mut representative_trace = None;
    let mut chosen_delivery_bound = 0;
    for iteration in 0..config.samples {
        let processing = execute_processing_sample(operation, nsp, tsp, (config.warmup + iteration) as u64)
            .map_err(invalid_input)?;
        let delivery_bound =
            delivery_bound_for(config.explicit_delivery_bound_ns, profile, &processing.trace);
        chosen_delivery_bound = delivery_bound;
        representative_trace.get_or_insert_with(|| processing.trace.clone());
        samples.push(compose_sample(
            kind,
            processing,
            profile,
            delivery_bound,
            seed_u64(operation, nsp, tsp, iteration as u64, b"sample"),
        ));
    }
    let trace = representative_trace.expect("sample count was validated");
    let summary = summarize(&samples);
    writeln!(
        output,
        "upspa {} {} {} {} {} {} 0 {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} completed {} {} {} {} {} {:.3} {:.3}",
        operation.name(),
        kind.name(),
        profile.map(|value| value.name).unwrap_or("none"),
        nsp,
        tsp,
        nsp,
        chosen_delivery_bound,
        config.samples,
        config.warmup,
        summary.client_ns,
        summary.provider_ns,
        summary.login_server_ns,
        summary.network_ns,
        summary.total_ns,
        summary.identification_stage_ns,
        summary.account_read_stage_ns,
        summary.prepare_stage_ns,
        summary.write_stage_ns,
        summary.terminal_stage_ns,
        trace.request_bytes(),
        trace.response_bytes(),
        trace.message_count(),
        trace.acknowledgement_count(),
        if config.rng_in_timed { 1 } else { 0 },
        summary.min_ns,
        summary.p50_ns,
        summary.p95_ns,
        summary.max_ns,
        summary.mean_ns,
        summary.stddev_ns,
    )
}

fn execute_processing_sample(
    operation: Operation,
    nsp: usize,
    tsp: usize,
    iteration: u64,
) -> Result<ProcessingSample, String> {
    let clock = DeterministicTestClock::new(iteration.saturating_add(1));
    let seed = seed_bytes(operation, nsp, tsp, iteration, b"fixture");
    let mut system =
        UpSpaSystem::with_seed_and_clock(nsp, tsp, seed, clock).map_err(|error| error.to_string())?;
    let uid = b"benchmark-user";
    let password = b"benchmark password";
    let new_password = b"new benchmark password";
    let lsj = b"benchmark-login-server";

    match operation {
        Operation::Setup => {
            let start = Instant::now();
            let outcome = system.setup(uid, password).map_err(|error| error.to_string())?;
            let processing_ns = elapsed_ns(start);
            assert_eq!(outcome.phase, PhaseKind::Setup);
            assert_eq!(outcome.result, crate::protocols::PhaseResult::Completed);
            assert!(system.providers.iter().all(|provider| {
                provider.identification_record(uid).is_some()
                    && provider.pending_identification(uid).is_none()
            }));
            Ok(processing_sample(processing_ns, outcome.trace))
        }
        Operation::Registration => {
            system.setup(uid, password).map_err(|error| error.to_string())?;
            let start = Instant::now();
            let outcome = system
                .registration(uid, password, lsj)
                .map_err(|error| error.to_string())?;
            let processing_ns = elapsed_ns(start);
            assert_eq!(outcome.phase, PhaseKind::Registration);
            assert_eq!(outcome.result, crate::protocols::PhaseResult::Completed);
            assert!(!system.has_pending_finalization(uid));
            let root = system
                .identify(
                    uid,
                    password,
                    crate::protocols::IdentificationRequirement::AllProviders,
                )
                .map_err(|error| error.to_string())?
                .state;
            assert!(system.providers.iter().all(|provider| {
                let suid = crate::crypto::hash_upspa_suid(&root.rsp, lsj, provider.provider_index());
                provider
                    .account_slot(&suid)
                    .is_some_and(|slot| slot.committed.is_some() && slot.pending.is_none())
            }));
            assert!(system.login_server.current_vinfo(uid).is_some());
            Ok(processing_sample(processing_ns, outcome.trace))
        }
        Operation::Authentication => {
            system.setup(uid, password).map_err(|error| error.to_string())?;
            system
                .registration(uid, password, lsj)
                .map_err(|error| error.to_string())?;
            let start = Instant::now();
            let outcome = system
                .authentication(uid, password, lsj)
                .map_err(|error| error.to_string())?;
            let processing_ns = elapsed_ns(start);
            if !outcome.authenticated {
                return Err("authentication benchmark fixture was rejected".into());
            }
            assert_eq!(outcome.selected_counter, 0);
            assert!(!system.has_pending_finalization(uid));
            Ok(processing_sample(processing_ns, outcome.trace))
        }
        Operation::SecretUpdate => {
            system.setup(uid, password).map_err(|error| error.to_string())?;
            system
                .registration(uid, password, lsj)
                .map_err(|error| error.to_string())?;
            let start = Instant::now();
            let outcome = system
                .secret_update(uid, password, lsj)
                .map_err(|error| error.to_string())?;
            assert_eq!(outcome.phase, PhaseKind::SecretUpdate);
            assert_eq!(outcome.result, crate::protocols::PhaseResult::Completed);
            let processing_ns = elapsed_ns(start);
            assert!(!system.has_pending_finalization(uid));
            let auth = system
                .authentication(uid, password, lsj)
                .map_err(|error| error.to_string())?;
            assert!(auth.authenticated);
            assert_eq!(auth.selected_counter, 1);
            Ok(processing_sample(processing_ns, outcome.trace))
        }
        Operation::PasswordUpdate => {
            system.setup(uid, password).map_err(|error| error.to_string())?;
            let old_records = system
                .providers
                .iter()
                .map(|provider| provider.identification_record(uid).unwrap().clone())
                .collect::<Vec<_>>();
            let start = Instant::now();
            let outcome = system
                .password_update(uid, password, new_password)
                .map_err(|error| error.to_string())?;
            assert_eq!(outcome.phase, PhaseKind::PasswordUpdate);
            assert_eq!(outcome.result, crate::protocols::PhaseResult::Completed);
            let processing_ns = elapsed_ns(start);
            assert!(!system.has_pending_finalization(uid));
            assert!(system
                .identify(
                    uid,
                    password,
                    crate::protocols::IdentificationRequirement::Threshold,
                )
                .is_err());
            let new_root = system
                .identify(
                    uid,
                    new_password,
                    crate::protocols::IdentificationRequirement::AllProviders,
                )
                .map_err(|error| error.to_string())?
                .state;
            assert!(system.providers.iter().zip(old_records).all(|(provider, old)| {
                let current = provider.identification_record(uid).unwrap();
                current.cid == new_root.cid
                    && current.share != old.share
                    && current.last_password_update_time > old.last_password_update_time
                    && provider.pending_identification(uid).is_none()
            }));
            Ok(processing_sample(processing_ns, outcome.trace))
        }
    }
}

fn processing_sample(processing_ns: u64, trace: ProtocolTrace) -> ProcessingSample {
    let provider_ns = trace.provider_processing_ns().min(processing_ns);
    let login_server_ns = trace
        .login_server_processing_ns()
        .min(processing_ns.saturating_sub(provider_ns));
    let client_ns = processing_ns.saturating_sub(provider_ns.saturating_add(login_server_ns));
    ProcessingSample {
        processing_ns,
        client_ns,
        provider_ns,
        login_server_ns,
        trace,
    }
}

fn compose_sample(
    kind: Kind,
    processing: ProcessingSample,
    profile: Option<NetProfile>,
    delivery_bound_ns: u64,
    jitter_seed: u64,
) -> Sample {
    let network = profile
        .map(|profile| simulate_trace(&processing.trace, profile, delivery_bound_ns, jitter_seed))
        .unwrap_or_default();
    let included_network = if kind.uses_network() { network.total_ns } else { 0 };
    let (client_ns, provider_ns, login_server_ns) = match kind {
        Kind::Client => (processing.client_ns, 0, 0),
        Kind::Provider => (0, processing.provider_ns, 0),
        Kind::LoginServer => (0, 0, processing.login_server_ns),
        Kind::FullNoNet | Kind::FullNet => (
            processing.client_ns,
            processing.provider_ns,
            processing.login_server_ns,
        ),
        Kind::NetOnly => (0, 0, 0),
    };
    let included_processing = match kind {
        Kind::Client => processing.client_ns,
        Kind::Provider => processing.provider_ns,
        Kind::LoginServer => processing.login_server_ns,
        Kind::FullNoNet | Kind::FullNet => processing.processing_ns,
        Kind::NetOnly => 0,
    };
    Sample {
        client_ns,
        provider_ns,
        login_server_ns,
        network,
        total_ns: included_processing.saturating_add(included_network),
    }
}

fn simulate_trace(
    trace: &ProtocolTrace,
    profile: NetProfile,
    delivery_bound_ns: u64,
    jitter_seed: u64,
) -> NetworkCost {
    let mut by_stage: BTreeMap<u32, Vec<&MessageEvent>> = BTreeMap::new();
    for event in &trace.events {
        by_stage.entry(event.stage_id).or_default().push(event);
    }
    let mut output = NetworkCost::default();
    let mut state = jitter_seed;
    for events in by_stage.values() {
        let mut stage_duration = 0;
        for event in events {
            let cost = event_network_cost(event, profile, delivery_bound_ns, &mut state);
            stage_duration = stage_duration.max(cost);
        }
        output.total_ns = output.total_ns.saturating_add(stage_duration);
        match events[0].stage {
            ProtocolStage::Identification => {
                output.identification_ns = output.identification_ns.saturating_add(stage_duration)
            }
            ProtocolStage::AccountRead | ProtocolStage::LoginServerAuthentication => {
                output.account_read_ns = output.account_read_ns.saturating_add(stage_duration)
            }
            ProtocolStage::ParallelProviderAndLsPrepare => {
                output.prepare_ns = output.prepare_ns.saturating_add(stage_duration)
            }
            ProtocolStage::Setup | ProtocolStage::AllProviderPendingWrites => {
                output.write_ns = output.write_ns.saturating_add(stage_duration)
            }
            ProtocolStage::ParallelTerminalAndProviderFinalAcks | ProtocolStage::AllProviderTerminalAcks => {
                output.terminal_ns = output.terminal_ns.saturating_add(stage_duration)
            }
        }
    }
    output
}

fn event_network_cost(
    event: &MessageEvent,
    profile: NetProfile,
    delivery_bound_ns: u64,
    jitter_state: &mut u64,
) -> u64 {
    if event.recipient_count == 0 {
        return 0;
    }
    let request_tx = tx_time_ns(
        event.request_bytes.saturating_add(profile.overhead_bytes),
        profile.bandwidth_bps,
    )
    .saturating_mul(event.recipient_count as u64);
    if matches!(event.wait_policy, WaitPolicy::OneWayDeliveryBound) {
        return request_tx.max(delivery_bound_ns);
    }
    let required_responses = match event.wait_policy {
        WaitPolicy::AllResponses => event.recipient_count,
        WaitPolicy::Threshold(value) | WaitPolicy::Quorum(value) => value.min(event.recipient_count),
        WaitPolicy::OneWayDeliveryBound => 0,
    };
    let response_tx = tx_time_ns(
        event.response_bytes.saturating_add(profile.overhead_bytes),
        profile.bandwidth_bps,
    )
    .saturating_mul(required_responses as u64);
    request_tx
        .saturating_add(profile.one_way_ns)
        .saturating_add(sample_positive_jitter(profile.jitter_ns, jitter_state))
        .saturating_add(response_tx)
        .saturating_add(profile.one_way_ns)
        .saturating_add(sample_positive_jitter(profile.jitter_ns, jitter_state))
}

fn delivery_bound_for(explicit: Option<u64>, profile: Option<NetProfile>, trace: &ProtocolTrace) -> u64 {
    if let Some(value) = explicit {
        return value;
    }
    let Some(profile) = profile else {
        return 0;
    };
    let largest_terminal_message = trace
        .events
        .iter()
        .filter(|event| matches!(event.wait_policy, WaitPolicy::OneWayDeliveryBound))
        .map(|event| event.request_bytes)
        .max()
        .unwrap_or(0);
    profile
        .one_way_ns
        .saturating_add(profile.jitter_ns)
        .saturating_add(tx_time_ns(
            largest_terminal_message.saturating_add(profile.overhead_bytes),
            profile.bandwidth_bps,
        ))
}

fn summarize(samples: &[Sample]) -> Summary {
    let totals = samples.iter().map(|sample| sample.total_ns).collect::<Vec<_>>();
    let min_ns = *totals.iter().min().unwrap();
    let max_ns = *totals.iter().max().unwrap();
    let p50_ns = percentile(&totals, 50);
    let p95_ns = percentile(&totals, 95);
    let mean_ns = totals.iter().map(|value| *value as f64).sum::<f64>() / totals.len() as f64;
    let stddev_ns = if totals.len() > 1 {
        let sum = totals
            .iter()
            .map(|value| {
                let delta = *value as f64 - mean_ns;
                delta * delta
            })
            .sum::<f64>();
        (sum / (totals.len() - 1) as f64).sqrt()
    } else {
        0.0
    };
    Summary {
        client_ns: median(samples.iter().map(|sample| sample.client_ns)),
        provider_ns: median(samples.iter().map(|sample| sample.provider_ns)),
        login_server_ns: median(samples.iter().map(|sample| sample.login_server_ns)),
        network_ns: median(samples.iter().map(|sample| sample.network.total_ns)),
        total_ns: p50_ns,
        identification_stage_ns: median(samples.iter().map(|sample| sample.network.identification_ns)),
        account_read_stage_ns: median(samples.iter().map(|sample| sample.network.account_read_ns)),
        prepare_stage_ns: median(samples.iter().map(|sample| sample.network.prepare_ns)),
        write_stage_ns: median(samples.iter().map(|sample| sample.network.write_ns)),
        terminal_stage_ns: median(samples.iter().map(|sample| sample.network.terminal_ns)),
        min_ns,
        p50_ns,
        p95_ns,
        max_ns,
        mean_ns,
        stddev_ns,
    }
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let index = ((sorted.len() - 1) * percentile + 99) / 100;
    sorted[index]
}

fn median(values: impl Iterator<Item = u64>) -> u64 {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    values[values.len() / 2]
}

fn elapsed_ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

fn tx_time_ns(bytes: usize, bandwidth_bps: u64) -> u64 {
    if bandwidth_bps == 0 {
        return 0;
    }
    let bits = bytes as u128 * 8;
    ((bits * 1_000_000_000 + bandwidth_bps as u128 - 1) / bandwidth_bps as u128).min(u64::MAX as u128) as u64
}

fn sample_positive_jitter(maximum: u64, state: &mut u64) -> u64 {
    if maximum == 0 {
        return 0;
    }
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state % maximum.saturating_add(1)
}

fn seed_bytes(operation: Operation, nsp: usize, tsp: usize, iteration: u64, domain: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"upspa/authoritative-benchmark/v1");
    hasher.update(domain);
    hasher.update(operation.name().as_bytes());
    hasher.update(&(nsp as u64).to_le_bytes());
    hasher.update(&(tsp as u64).to_le_bytes());
    hasher.update(&iteration.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn seed_u64(operation: Operation, nsp: usize, tsp: usize, iteration: u64, domain: &[u8]) -> u64 {
    let seed = seed_bytes(operation, nsp, tsp, iteration, domain);
    u64::from_le_bytes(seed[..8].try_into().unwrap())
}

fn thresholds_for(config: &Config, nsp: usize) -> io::Result<Vec<usize>> {
    let values = if let Some(explicit) = &config.tsp {
        explicit.clone()
    } else {
        config
            .tsp_pct
            .iter()
            .map(|percentage| ((nsp as u128 * *percentage as u128 + 99) / 100) as usize)
            .collect()
    };
    for &tsp in &values {
        if tsp == 0 || tsp > nsp {
            return Err(invalid_input(format!("invalid UpSPA tuple nsp={nsp}, tsp={tsp}")));
        }
    }
    Ok(values)
}

fn parse_args(args: Vec<String>) -> Result<Config, String> {
    let mut kinds = vec![Kind::FullNoNet];
    let mut operations = Operation::ALL.to_vec();
    let mut nsp = vec![3];
    let mut tsp = Some(vec![2]);
    let mut tsp_pct = Vec::new();
    let mut samples = 10;
    let mut warmup = 2;
    let mut output = "upspa_benchmark.dat".to_owned();
    let mut rng_in_timed = false;
    let mut scheme_selected = true;
    let mut net_selection = "all".to_owned();
    let mut delivery_bound_ms = None;
    let mut lan_rtt_ms = 0.5;
    let mut lan_jitter_ms = 0.05;
    let mut lan_bw_mbps = 1000.0;
    let mut wan_rtt_ms = 60.0;
    let mut wan_jitter_ms = 5.0;
    let mut wan_bw_mbps = 50.0;
    let mut overhead_bytes = 64;

    let mut index = 0;
    while index < args.len() {
        let flag = &args[index];
        let value = |index: &mut usize| -> Result<&str, String> {
            *index += 1;
            args.get(*index)
                .map(String::as_str)
                .ok_or_else(|| format!("missing value for {flag}"))
        };
        match flag.as_str() {
            "--scheme" => {
                let selected = value(&mut index)?
                    .split(',')
                    .map(|item| item.trim().to_ascii_lowercase())
                    .collect::<Vec<_>>();
                scheme_selected = selected.iter().any(|item| item == "upspa" || item == "all");
            }
            "--kind" => kinds = parse_kinds(value(&mut index)?)?,
            "--ops" => operations = parse_operations(value(&mut index)?)?,
            "--nsp" => nsp = parse_usize_list(value(&mut index)?)?,
            "--tsp" => {
                tsp = Some(parse_usize_list(value(&mut index)?)?);
                tsp_pct.clear();
            }
            "--tsp-pct" => {
                tsp_pct = parse_u32_list(value(&mut index)?)?;
                tsp = None;
            }
            "--sample-size" => samples = parse_usize(value(&mut index)?, flag)?,
            "--warmup-iters" => warmup = parse_usize(value(&mut index)?, flag)?,
            "--out" => output = value(&mut index)?.to_owned(),
            "--rng-in-timed" | "--rng" => rng_in_timed = true,
            "--net" => net_selection = value(&mut index)?.to_ascii_lowercase(),
            "--delivery-bound-ms" => delivery_bound_ms = Some(parse_f64(value(&mut index)?, flag)?),
            "--lan-rtt-ms" => lan_rtt_ms = parse_f64(value(&mut index)?, flag)?,
            "--lan-jitter-ms" => lan_jitter_ms = parse_f64(value(&mut index)?, flag)?,
            "--lan-bw-mbps" => lan_bw_mbps = parse_f64(value(&mut index)?, flag)?,
            "--wan-rtt-ms" => wan_rtt_ms = parse_f64(value(&mut index)?, flag)?,
            "--wan-jitter-ms" => wan_jitter_ms = parse_f64(value(&mut index)?, flag)?,
            "--wan-bw-mbps" => wan_bw_mbps = parse_f64(value(&mut index)?, flag)?,
            "--overhead-bytes" => overhead_bytes = parse_usize(value(&mut index)?, flag)?,
            // Accepted as no-ops for root-CLI and legacy compatibility. UpSPA has one
            // authoritative password update and does not use qsp/offline/proc calibration.
            "--pwdupd" | "--qsp" | "--offline" | "--proc-warmup" | "--proc-samples" => {
                let _ = value(&mut index)?;
            }
            "--pwdupd-v2" => {}
            "--help" | "-h" => return Err(help_text().into()),
            unknown if unknown.starts_with('-') => {
                return Err(format!("unknown UpSPA benchmark flag: {unknown}"));
            }
            _ => {}
        }
        index += 1;
    }
    if samples == 0 {
        return Err("--sample-size must be positive".into());
    }
    if nsp.is_empty() || kinds.is_empty() || operations.is_empty() {
        return Err("benchmark grids must not be empty".into());
    }
    if tsp.is_none() && tsp_pct.is_empty() {
        return Err("--tsp-pct must not be empty".into());
    }
    let lan = NetProfile {
        name: "lan",
        one_way_ns: ms_to_ns(lan_rtt_ms / 2.0),
        jitter_ns: ms_to_ns(lan_jitter_ms),
        bandwidth_bps: mbps_to_bps(lan_bw_mbps),
        overhead_bytes,
    };
    let wan = NetProfile {
        name: "wan",
        one_way_ns: ms_to_ns(wan_rtt_ms / 2.0),
        jitter_ns: ms_to_ns(wan_jitter_ms),
        bandwidth_bps: mbps_to_bps(wan_bw_mbps),
        overhead_bytes,
    };
    let profiles = match net_selection.as_str() {
        "lan" => vec![lan],
        "wan" => vec![wan],
        "all" => vec![lan, wan],
        other => return Err(format!("invalid --net value: {other}")),
    };
    Ok(Config {
        scheme_selected,
        kinds,
        operations,
        nsp,
        tsp,
        tsp_pct,
        samples,
        warmup,
        output,
        rng_in_timed,
        profiles,
        explicit_delivery_bound_ns: delivery_bound_ms.map(ms_to_ns),
    })
}

fn parse_kinds(value: &str) -> Result<Vec<Kind>, String> {
    let mut output = Vec::new();
    for raw in value.split(',') {
        let normalized = raw.trim().to_ascii_lowercase().replace('-', "_");
        if normalized.is_empty() {
            continue;
        }
        if normalized == "all" {
            return Ok(Kind::ALL.to_vec());
        }
        let kind = match normalized.as_str() {
            "client" | "proto" | "prim" => Kind::Client,
            "provider" | "sp" => Kind::Provider,
            "login_server" | "ls" => Kind::LoginServer,
            "full_no_net" => Kind::FullNoNet,
            "net_only" | "net" => Kind::NetOnly,
            "full_net" | "full" => Kind::FullNet,
            _ => return Err(format!("invalid UpSPA benchmark kind: {raw}")),
        };
        if !output.contains(&kind) {
            output.push(kind);
        }
    }
    Ok(output)
}

fn parse_operations(value: &str) -> Result<Vec<Operation>, String> {
    let mut output = Vec::new();
    for raw in value.split(',') {
        let normalized = raw.trim().to_ascii_lowercase().replace('-', "_");
        if normalized.is_empty() {
            continue;
        }
        if normalized == "all" {
            return Ok(Operation::ALL.to_vec());
        }
        let operation = match normalized.as_str() {
            "setup" => Operation::Setup,
            "reg" | "registration" => Operation::Registration,
            "auth" | "authentication" => Operation::Authentication,
            "secupd" | "secret_update" => Operation::SecretUpdate,
            "pwdupd" | "password_update" => Operation::PasswordUpdate,
            _ => return Err(format!("invalid UpSPA operation: {raw}")),
        };
        if !output.contains(&operation) {
            output.push(operation);
        }
    }
    Ok(output)
}

fn parse_usize_list(value: &str) -> Result<Vec<usize>, String> {
    value
        .split(',')
        .filter(|item| !item.trim().is_empty())
        .map(|item| parse_usize(item.trim(), "list"))
        .collect()
}

fn parse_u32_list(value: &str) -> Result<Vec<u32>, String> {
    value
        .split(',')
        .filter(|item| !item.trim().is_empty())
        .map(|item| {
            item.trim()
                .parse::<u32>()
                .map_err(|_| format!("invalid integer: {item}"))
        })
        .collect()
}

fn parse_usize(value: &str, flag: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("invalid integer for {flag}: {value}"))
}

fn parse_f64(value: &str, flag: &str) -> Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|_| format!("invalid number for {flag}: {value}"))?;
    if parsed.is_finite() && parsed >= 0.0 {
        Ok(parsed)
    } else {
        Err(format!("{flag} must be a finite non-negative number"))
    }
}

fn ms_to_ns(value: f64) -> u64 {
    (value * 1_000_000.0).round().min(u64::MAX as f64) as u64
}

fn mbps_to_bps(value: f64) -> u64 {
    (value * 1_000_000.0).round().min(u64::MAX as f64) as u64
}

fn invalid_input(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

fn help_text() -> &'static str {
    "UpSPA benchmark flags: --kind client,provider,login-server,full-no-net,net-only,full-net --ops setup,reg,auth,secupd,pwdupd,all --nsp N[,N] --tsp T[,T] --sample-size N --warmup-iters N --net lan|wan|all --delivery-bound-ms N --out FILE"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_schema_has_exactly_thirty_three_columns() {
        assert_eq!(HEADER.split_whitespace().count(), 33);
    }

    #[test]
    fn trace_network_model_consumes_emitted_stages() {
        let processing = execute_processing_sample(Operation::Registration, 3, 2, 0).unwrap();
        assert_eq!(
            processing.trace.stage_order(),
            vec![
                ProtocolStage::Identification,
                ProtocolStage::ParallelProviderAndLsPrepare,
                ProtocolStage::ParallelTerminalAndProviderFinalAcks,
            ]
        );
        let profile = NetProfile {
            name: "test",
            one_way_ns: 100,
            jitter_ns: 0,
            bandwidth_bps: 1_000_000_000,
            overhead_bytes: 0,
        };
        let cost = simulate_trace(&processing.trace, profile, 100, 1);
        assert!(cost.identification_ns > 0);
        assert!(cost.prepare_ns > 0);
        assert!(cost.terminal_ns > 0);
        assert_eq!(
            cost.total_ns,
            cost.identification_ns + cost.prepare_ns + cost.terminal_ns
        );
    }

    #[test]
    fn component_rows_report_only_measured_role_work_and_full_rows_report_all_roles() {
        let processing = execute_processing_sample(Operation::Registration, 3, 2, 0).unwrap();
        assert!(processing.processing_ns > 0);
        assert!(processing.client_ns > 0);
        assert!(processing.provider_ns > 0);
        assert!(processing.login_server_ns > 0);
        assert_eq!(
            processing.client_ns + processing.provider_ns + processing.login_server_ns,
            processing.processing_ns
        );

        let client = compose_sample(Kind::Client, processing.clone(), None, 0, 1);
        assert_eq!(client.total_ns, processing.client_ns);
        assert_eq!(client.provider_ns, 0);
        assert_eq!(client.login_server_ns, 0);

        let provider = compose_sample(Kind::Provider, processing.clone(), None, 0, 1);
        assert_eq!(provider.total_ns, processing.provider_ns);
        assert_eq!(provider.client_ns, 0);
        assert_eq!(provider.login_server_ns, 0);

        let login_server = compose_sample(Kind::LoginServer, processing.clone(), None, 0, 1);
        assert_eq!(login_server.total_ns, processing.login_server_ns);
        assert_eq!(login_server.client_ns, 0);
        assert_eq!(login_server.provider_ns, 0);

        let full = compose_sample(Kind::FullNoNet, processing.clone(), None, 0, 1);
        assert_eq!(full.total_ns, processing.processing_ns);
        assert_eq!(full.client_ns, processing.client_ns);
        assert_eq!(full.provider_ns, processing.provider_ns);
        assert_eq!(full.login_server_ns, processing.login_server_ns);
    }

    #[test]
    fn smoke_run_emits_only_complete_thirty_three_column_upspa_rows() {
        let path = std::env::temp_dir().join(format!("upspa-authoritative-smoke-{}.dat", std::process::id()));
        run(vec![
            "--scheme".into(),
            "upspa".into(),
            "--kind".into(),
            "full-no-net".into(),
            "--ops".into(),
            "all".into(),
            "--nsp".into(),
            "3".into(),
            "--tsp".into(),
            "2".into(),
            "--sample-size".into(),
            "1".into(),
            "--warmup-iters".into(),
            "0".into(),
            "--out".into(),
            path.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 6);
        assert_eq!(lines[0], HEADER);
        for row in &lines[1..] {
            assert_eq!(row.split_whitespace().count(), 33, "{row}");
            assert!(row.starts_with("upspa "));
            assert!(row.contains(" completed "));
            let fields = row.split_whitespace().collect::<Vec<_>>();
            let client_ns = fields[11].parse::<u64>().unwrap();
            let provider_ns = fields[12].parse::<u64>().unwrap();
            let login_server_ns = fields[13].parse::<u64>().unwrap();
            let network_ns = fields[14].parse::<u64>().unwrap();
            let total_ns = fields[15].parse::<u64>().unwrap();
            assert!(client_ns > 0, "full phase must report client work: {row}");
            assert!(provider_ns > 0, "full phase must report provider work: {row}");
            assert_eq!(network_ns, 0);
            assert_eq!(client_ns + provider_ns + login_server_ns, total_ns);
        }
    }
}
