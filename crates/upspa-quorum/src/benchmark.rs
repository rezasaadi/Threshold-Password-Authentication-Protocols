use crate::protocols::login_server::PendingLsOperation;
use crate::protocols::messages::{ProtocolStage, ProtocolTrace, WaitPolicy};
use crate::protocols::provider::{ReplicaStatus, RoUpSpaProvider};
use crate::protocols::roupspa::{
    minimum_quorum_size, seed_for, validate_thresholds, InFlightOperation, PhaseResult, RoUpSpaSystem,
};
use std::collections::HashMap;
use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::time::Instant;

const KINDS: [&str; 6] = [
    "client",
    "provider",
    "login_server",
    "full_no_net",
    "net_only",
    "full_net",
];
const OPS: [&str; 7] = [
    "setup",
    "reg",
    "auth",
    "secupd",
    "pwdupd",
    "sync_ident",
    "sync_account",
];
const HEADER: &str = "scheme phase kind net_profile nsp tsp qsp unavailable delivery_bound_ns samples warmup client_ns provider_ns login_server_ns network_ns total_ns identification_stage_ns account_read_stage_ns prepare_stage_ns write_stage_ns terminal_stage_ns request_bytes response_bytes message_count acknowledgement_count result rng_in_timed min_ns p50_ns p95_ns max_ns mean_ns stddev_ns";

#[derive(Clone, Debug)]
struct Stats {
    min: u128,
    p50: u128,
    p95: u128,
    max: u128,
    mean: f64,
    stddev: f64,
}

fn stats(mut values: Vec<u128>) -> Stats {
    assert!(!values.is_empty());
    values.sort_unstable();
    let count = values.len();
    let mean = values.iter().map(|value| *value as f64).sum::<f64>() / count as f64;
    let variance = if count > 1 {
        values
            .iter()
            .map(|value| {
                let delta = *value as f64 - mean;
                delta * delta
            })
            .sum::<f64>()
            / (count - 1) as f64
    } else {
        0.0
    };
    Stats {
        min: values[0],
        p50: values[count / 2],
        p95: values[((count - 1) * 95) / 100],
        max: values[count - 1],
        mean,
        stddev: variance.sqrt(),
    }
}

fn mean_u128(values: &[u128]) -> u128 {
    values.iter().sum::<u128>() / values.len() as u128
}

#[derive(Clone, Copy, Debug)]
struct NetProfile {
    name: &'static str,
    one_way_ns: u64,
    jitter_ns: u64,
    bandwidth_bps: u64,
    overhead_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct NetworkCost {
    total: u64,
    identification: u64,
    account_read: u64,
    prepare: u64,
    write: u64,
    terminal: u64,
}

#[derive(Clone, Debug)]
enum Offline {
    Max,
    Count(usize),
}

#[derive(Clone, Debug)]
struct Config {
    kinds: Vec<String>,
    ops: Vec<String>,
    nsp: Vec<usize>,
    tsp: Option<Vec<usize>>,
    tsp_pct: Option<Vec<u32>>,
    qsp: Option<Vec<usize>>,
    unavailable: Offline,
    samples: usize,
    warmup: usize,
    output: String,
    net: String,
    lan_rtt_ms: f64,
    lan_jitter_ms: f64,
    lan_bw_mbps: f64,
    wan_rtt_ms: f64,
    wan_jitter_ms: f64,
    wan_bw_mbps: f64,
    overhead_bytes: usize,
    delivery_bound_ms: Option<f64>,
    rng_in_timed: bool,
}

fn parse_usize_list(value: &str) -> Vec<usize> {
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| part.trim().parse().expect("invalid integer list"))
        .collect()
}

fn parse_u32_list(value: &str) -> Vec<u32> {
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| part.trim().parse().expect("invalid integer list"))
        .collect()
}

fn parse_names(value: &str, all: &[&str]) -> Vec<String> {
    if value.eq_ignore_ascii_case("all") {
        return all.iter().map(|name| (*name).to_owned()).collect();
    }
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| {
            let mut name = part.trim().to_ascii_lowercase().replace('-', "_");
            if name == "sync_identification" {
                name = "sync_ident".into();
            }
            name
        })
        .collect()
}

fn parse_args(args: Vec<String>) -> Config {
    let mut config = Config {
        kinds: vec!["full_no_net".into()],
        ops: OPS[..5].iter().map(|name| (*name).to_owned()).collect(),
        nsp: vec![3],
        tsp: Some(vec![2]),
        tsp_pct: None,
        qsp: None,
        unavailable: Offline::Count(0),
        samples: 50,
        warmup: 10,
        output: "roupspa_bench.dat".into(),
        net: "all".into(),
        lan_rtt_ms: 0.6,
        lan_jitter_ms: 0.05,
        lan_bw_mbps: 1_000.0,
        wan_rtt_ms: 80.0,
        wan_jitter_ms: 5.0,
        wan_bw_mbps: 100.0,
        overhead_bytes: 64,
        delivery_bound_ms: None,
        rng_in_timed: false,
    };
    let mut index = 0;
    while index < args.len() {
        let flag = &args[index];
        index += 1;
        let mut value = || {
            let result = args
                .get(index)
                .unwrap_or_else(|| panic!("missing value for {flag}"));
            index += 1;
            result.clone()
        };
        match flag.as_str() {
            "--help" | "-h" => {
                println!("RoUpSPA benchmark: --kind --ops --nsp --tsp/--tsp-pct [--qsp] --offline --sample-size --warmup-iters --net --delivery-bound-ms --out");
                return config;
            }
            "--scheme" => {
                let _ = value();
            }
            "--kind" => config.kinds = parse_names(&value(), &KINDS),
            "--ops" => config.ops = parse_names(&value(), &OPS),
            "--nsp" => config.nsp = parse_usize_list(&value()),
            "--tsp" => {
                config.tsp = Some(parse_usize_list(&value()));
                config.tsp_pct = None;
            }
            "--tsp-pct" => {
                config.tsp_pct = Some(parse_u32_list(&value()));
                config.tsp = None;
            }
            "--qsp" => config.qsp = Some(parse_usize_list(&value())),
            "--offline" | "--unavailable" => {
                let raw = value().to_ascii_lowercase();
                config.unavailable = match raw.as_str() {
                    "max" => Offline::Max,
                    "none" | "0" | "zero" => Offline::Count(0),
                    _ => Offline::Count(raw.parse().expect("invalid --offline value")),
                };
            }
            "--sample-size" => config.samples = value().parse().expect("invalid sample size"),
            "--warmup-iters" => config.warmup = value().parse().expect("invalid warmup"),
            "--out" => config.output = value(),
            "--net" => config.net = value().to_ascii_lowercase(),
            "--lan-rtt-ms" => config.lan_rtt_ms = value().parse().expect("invalid LAN RTT"),
            "--lan-jitter-ms" => config.lan_jitter_ms = value().parse().expect("invalid LAN jitter"),
            "--lan-bw-mbps" => config.lan_bw_mbps = value().parse().expect("invalid LAN bandwidth"),
            "--wan-rtt-ms" => config.wan_rtt_ms = value().parse().expect("invalid WAN RTT"),
            "--wan-jitter-ms" => config.wan_jitter_ms = value().parse().expect("invalid WAN jitter"),
            "--wan-bw-mbps" => config.wan_bw_mbps = value().parse().expect("invalid WAN bandwidth"),
            "--overhead-bytes" => config.overhead_bytes = value().parse().expect("invalid framing overhead"),
            "--delivery-bound-ms" => {
                config.delivery_bound_ms = Some(value().parse().expect("invalid delivery bound"))
            }
            "--rng-in-timed" | "--rng" => config.rng_in_timed = true,
            "--bench" => {}
            unknown => panic!("unknown RoUpSPA benchmark argument: {unknown}"),
        }
    }
    assert!(config.samples > 0, "sample size must be positive");
    for kind in &config.kinds {
        assert!(KINDS.contains(&kind.as_str()), "unknown benchmark kind: {kind}");
    }
    for op in &config.ops {
        assert!(OPS.contains(&op.as_str()), "unknown RoUpSPA operation: {op}");
    }
    config
}

fn threshold_tuples(config: &Config) -> Vec<(usize, usize, usize)> {
    let mut tuples = Vec::new();
    for &nsp in &config.nsp {
        let thresholds = if let Some(values) = &config.tsp {
            values.clone()
        } else {
            config
                .tsp_pct
                .as_ref()
                .expect("threshold selection")
                .iter()
                .map(|percent| ((nsp as u128 * *percent as u128 + 99) / 100) as usize)
                .collect()
        };
        for tsp in thresholds {
            let quorums = config
                .qsp
                .clone()
                .unwrap_or_else(|| vec![minimum_quorum_size(nsp, tsp).expect("valid nsp/tsp")]);
            for qsp in quorums {
                validate_thresholds(nsp, tsp, qsp).expect("invalid explicit RoUpSPA tuple");
                tuples.push((nsp, tsp, qsp));
            }
        }
    }
    tuples
}

fn profiles(config: &Config) -> Vec<NetProfile> {
    let to_ns = |milliseconds: f64| (milliseconds * 1_000_000.0).round() as u64;
    let to_bps = |megabits: f64| (megabits * 1_000_000.0).round() as u64;
    let lan = NetProfile {
        name: "lan",
        one_way_ns: to_ns(config.lan_rtt_ms / 2.0),
        jitter_ns: to_ns(config.lan_jitter_ms),
        bandwidth_bps: to_bps(config.lan_bw_mbps),
        overhead_bytes: config.overhead_bytes,
    };
    let wan = NetProfile {
        name: "wan",
        one_way_ns: to_ns(config.wan_rtt_ms / 2.0),
        jitter_ns: to_ns(config.wan_jitter_ms),
        bandwidth_bps: to_bps(config.wan_bw_mbps),
        overhead_bytes: config.overhead_bytes,
    };
    match config.net.as_str() {
        "lan" => vec![lan],
        "wan" => vec![wan],
        "all" => vec![lan, wan],
        _ => panic!("--net must be lan, wan, or all"),
    }
}

fn transmit_ns(bytes: usize, bandwidth_bps: u64) -> u64 {
    let bits = bytes as u128 * 8;
    ((bits * 1_000_000_000 + bandwidth_bps as u128 - 1) / bandwidth_bps as u128) as u64
}

fn deterministic_jitter(seed: &mut u64, maximum: u64) -> i128 {
    if maximum == 0 {
        return 0;
    }
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    (*seed % (maximum * 2 + 1)) as i128 - maximum as i128
}

fn round_cost(
    recipients: usize,
    wait_for: usize,
    request_bytes: usize,
    response_bytes: usize,
    profile: NetProfile,
    jitter_seed: &mut u64,
) -> u64 {
    if recipients == 0 || wait_for == 0 {
        return 0;
    }
    let request_tx = transmit_ns(request_bytes + profile.overhead_bytes, profile.bandwidth_bps);
    let response_tx = transmit_ns(response_bytes + profile.overhead_bytes, profile.bandwidth_bps);
    let mut arrivals = Vec::with_capacity(recipients);
    let mut uplink = 0_u64;
    for _ in 0..recipients {
        uplink = uplink.saturating_add(request_tx);
        let jitter = deterministic_jitter(jitter_seed, profile.jitter_ns);
        let request_arrival = (uplink as i128 + profile.one_way_ns as i128 + jitter).max(0) as u64;
        let jitter = deterministic_jitter(jitter_seed, profile.jitter_ns);
        let response_arrival =
            (request_arrival as i128 + response_tx as i128 + profile.one_way_ns as i128 + jitter).max(0)
                as u64;
        arrivals.push(response_arrival);
    }
    arrivals.sort_unstable();
    arrivals[wait_for.min(arrivals.len()) - 1]
}

fn chosen_delivery_bound(config: &Config, profile: NetProfile, terminal_request_bytes: usize) -> u64 {
    config
        .delivery_bound_ms
        .map(|milliseconds| (milliseconds * 1_000_000.0).round() as u64)
        .unwrap_or_else(|| {
            profile
                .one_way_ns
                .saturating_add(profile.jitter_ns)
                .saturating_add(transmit_ns(
                    terminal_request_bytes + profile.overhead_bytes,
                    profile.bandwidth_bps,
                ))
        })
}

fn network_cost(
    trace: &ProtocolTrace,
    profile: NetProfile,
    config: &Config,
    seed: u64,
) -> (NetworkCost, u64) {
    let terminal_bytes = trace
        .events
        .iter()
        .filter(|event| matches!(event.wait_policy, WaitPolicy::OneWayDeliveryBound))
        .map(|event| event.request_bytes)
        .max()
        .unwrap_or(0);
    let delivery_bound = chosen_delivery_bound(config, profile, terminal_bytes);
    let mut jitter_seed = seed.max(1);
    let mut stage_costs = std::collections::BTreeMap::<u32, (u64, ProtocolStage)>::new();
    for event in &trace.events {
        let cost = match event.wait_policy {
            WaitPolicy::OneWayDeliveryBound => delivery_bound,
            WaitPolicy::AllResponses => round_cost(
                event.recipient_count,
                event.recipient_count,
                event.request_bytes,
                event.response_bytes,
                profile,
                &mut jitter_seed,
            ),
            WaitPolicy::Threshold(required) | WaitPolicy::Quorum(required) => round_cost(
                event.recipient_count,
                required,
                event.request_bytes,
                event.response_bytes,
                profile,
                &mut jitter_seed,
            ),
        };
        stage_costs
            .entry(event.stage_id)
            .and_modify(|entry| entry.0 = entry.0.max(cost))
            .or_insert((cost, event.stage));
    }
    let mut result = NetworkCost::default();
    for (_, (cost, stage)) in stage_costs {
        result.total = result.total.saturating_add(cost);
        match stage {
            ProtocolStage::Identification | ProtocolStage::IdentificationOld => {
                result.identification = result.identification.saturating_add(cost)
            }
            ProtocolStage::AccountRead => result.account_read = result.account_read.saturating_add(cost),
            ProtocolStage::LsPrepare => result.prepare = result.prepare.saturating_add(cost),
            ProtocolStage::ProviderQuorumWrite
            | ProtocolStage::QuorumTentativeWrites
            | ProtocolStage::ToprfNewSameShares
            | ProtocolStage::SetupWrite
            | ProtocolStage::SynchronizationRead => result.write = result.write.saturating_add(cost),
            ProtocolStage::LsTerminalDelivery | ProtocolStage::OneWayProviderStore => {
                result.terminal = result.terminal.saturating_add(cost)
            }
            ProtocolStage::LsAuthentication => result.prepare = result.prepare.saturating_add(cost),
        }
    }
    (result, delivery_bound)
}

fn completed(result: &PhaseResult) -> bool {
    matches!(
        result,
        PhaseResult::Completed {
            decision: None | Some(true),
            ..
        }
    )
}

fn maximum_unavailable_for_operation(op: &str, nsp: usize, tsp: usize, qsp: usize) -> usize {
    match op {
        "setup" => 0,
        "auth" => nsp.saturating_sub(tsp),
        "reg" | "secupd" | "pwdupd" | "sync_ident" | "sync_account" => nsp.saturating_sub(qsp),
        _ => unreachable!("validated RoUpSPA operation"),
    }
}

fn unavailable_for_operation(configured: &Offline, op: &str, nsp: usize, tsp: usize, qsp: usize) -> usize {
    let maximum = maximum_unavailable_for_operation(op, nsp, tsp, qsp);
    if op == "setup" {
        return 0;
    }
    match configured {
        Offline::Max => maximum,
        Offline::Count(value) => {
            assert!(
                *value <= maximum,
                "unavailable providers exceed RoUpSPA {op} progress bound ({maximum})"
            );
            *value
        }
    }
}

fn validate_operation_tuple(op: &str, nsp: usize, qsp: usize) {
    if matches!(op, "sync_ident" | "sync_account") {
        assert!(
            qsp < nsp,
            "RoUpSPA synchronization requires qsp < nsp so the recovering replica has qsp donors"
        );
    }
}

fn prepare_system(
    op: &str,
    nsp: usize,
    tsp: usize,
    qsp: usize,
    unavailable: usize,
    iteration: u64,
) -> (RoUpSpaSystem, Option<usize>) {
    let seed = seed_for(b"benchmark/system", nsp, tsp, iteration);
    let mut system = RoUpSpaSystem::new(nsp, tsp, qsp, seed).expect("valid benchmark tuple");
    if op == "setup" {
        return (system, None);
    }
    assert!(completed(&system.setup()), "setup precondition");
    let recover_index = nsp.checked_sub(1);
    match op {
        "reg" | "pwdupd" => {
            system.set_rotating_unavailable(unavailable, iteration as usize);
        }
        "auth" | "secupd" => {
            assert!(completed(&system.registration()), "registration precondition");
            system.set_rotating_unavailable(unavailable, iteration as usize);
        }
        "sync_ident" => {
            let recover = recover_index.expect("positive nsp");
            assert!(qsp < nsp, "identification synchronization requires qsp < nsp");
            let stale_count = unavailable.max(1).min(nsp - qsp);
            system.set_rotating_unavailable(stale_count, recover + 1 - stale_count);
            system.providers[recover].reachable = false;
            assert!(
                completed(&system.password_update()),
                "password update precondition"
            );
            system.providers[recover].reachable = true;
        }
        "sync_account" => {
            let recover = recover_index.expect("positive nsp");
            assert!(qsp < nsp, "account synchronization requires qsp < nsp");
            let stale_count = unavailable.max(1).min(nsp - qsp);
            system.set_rotating_unavailable(stale_count, recover + 1 - stale_count);
            system.providers[recover].reachable = false;
            assert!(completed(&system.registration()), "registration precondition");
            system.providers[recover].reachable = true;
        }
        _ => unreachable!(),
    }
    (system, recover_index)
}

fn execute(system: &mut RoUpSpaSystem, op: &str, recover_index: Option<usize>) -> PhaseResult {
    match op {
        "setup" => system.setup(),
        "reg" => system.registration(),
        "auth" => system.authentication(),
        "secupd" => system.secret_update(),
        "pwdupd" => system.password_update(),
        "sync_ident" => match system.synchronize_identification(recover_index.expect("recoverer")) {
            Ok(outcome) => PhaseResult::Completed {
                acknowledgements: outcome.valid_responses,
                record_digest: [0; 32],
                decision: None,
                trace: outcome.trace,
            },
            Err(error) => PhaseResult::Aborted {
                error,
                trace: system.last_trace.clone(),
            },
        },
        "sync_account" => {
            let key = system.any_account_family().expect("account precondition");
            match system.synchronize_account(&key.uid, key.suid, recover_index.expect("recoverer")) {
                Ok(outcome) => PhaseResult::Completed {
                    acknowledgements: outcome.valid_responses,
                    record_digest: [0; 32],
                    decision: None,
                    trace: outcome.trace,
                },
                Err(error) => PhaseResult::Aborted {
                    error,
                    trace: system.last_trace.clone(),
                },
            }
        }
        _ => unreachable!(),
    }
}

#[derive(Clone, Debug)]
struct Sample {
    client: u128,
    provider: u128,
    login_server: u128,
    network: u128,
    total: u128,
    network_cost: NetworkCost,
    delivery_bound: u64,
    trace: ProtocolTrace,
}

#[derive(Clone, Debug)]
struct BenchmarkState {
    providers: Vec<RoUpSpaProvider>,
    login_current: HashMap<Vec<u8>, [u8; 32]>,
    login_pending: HashMap<Vec<u8>, PendingLsOperation>,
    password: Vec<u8>,
}

fn capture_state(system: &RoUpSpaSystem) -> BenchmarkState {
    BenchmarkState {
        providers: system.providers.clone(),
        login_current: system.login_server.current.clone(),
        login_pending: system.login_server.pending.clone(),
        password: system.password.clone(),
    }
}

fn assert_phase_postconditions(
    system: &RoUpSpaSystem,
    op: &str,
    recover_index: Option<usize>,
    result: &PhaseResult,
    before: &BenchmarkState,
) {
    assert!(completed(result), "benchmark phase must complete: {result:?}");
    let (acknowledgements, decision) = match result {
        PhaseResult::Completed {
            acknowledgements,
            decision,
            trace,
            ..
        } => {
            assert_eq!(trace, &system.last_trace);
            (*acknowledgements, *decision)
        }
        _ => unreachable!("completed result checked above"),
    };
    let expected_stages: &[ProtocolStage] = match op {
        "setup" => &[ProtocolStage::SetupWrite],
        "reg" => &[
            ProtocolStage::Identification,
            ProtocolStage::LsPrepare,
            ProtocolStage::ProviderQuorumWrite,
            ProtocolStage::LsTerminalDelivery,
        ],
        "auth" => &[
            ProtocolStage::Identification,
            ProtocolStage::AccountRead,
            ProtocolStage::LsAuthentication,
        ],
        "secupd" => &[
            ProtocolStage::Identification,
            ProtocolStage::AccountRead,
            ProtocolStage::LsPrepare,
            ProtocolStage::ProviderQuorumWrite,
            ProtocolStage::LsTerminalDelivery,
        ],
        "pwdupd" => &[
            ProtocolStage::IdentificationOld,
            ProtocolStage::ToprfNewSameShares,
            ProtocolStage::QuorumTentativeWrites,
            ProtocolStage::OneWayProviderStore,
        ],
        "sync_ident" | "sync_account" => &[ProtocolStage::SynchronizationRead],
        _ => unreachable!("validated RoUpSPA operation"),
    };
    assert_eq!(result.trace().stages(), expected_stages);
    assert!(result.trace().terminal_events_have_no_response());
    match op {
        "setup" => {
            assert_eq!(acknowledgements, system.nsp);
            assert_eq!(decision, None);
            assert!(system.initialized, "setup must initialize the system");
            assert!(system.providers.iter().all(|provider| {
                provider.share(&system.uid).is_some()
                    && provider.identifications.get(&system.uid).is_some_and(|replica| {
                        replica.status == ReplicaStatus::Active
                            && replica.current.ctrid == 0
                            && replica.current.signature.is_none()
                            && replica.tentative_identification.is_none()
                    })
            }));
        }
        "reg" | "secupd" => {
            assert_eq!(decision, None);
            assert!(acknowledgements >= system.qsp);
            let expected_counter = if op == "secupd" { 1 } else { 0 };
            let key = system.any_account_family().expect("completed account family");
            let active = system
                .providers
                .iter()
                .filter_map(|provider| provider.accounts.get(&key))
                .filter(|replica| replica.status == ReplicaStatus::Active)
                .filter_map(|replica| replica.current.as_ref())
                .collect::<Vec<_>>();
            assert_eq!(active.len(), acknowledgements);
            assert!(active.iter().all(|record| record.ctr == expected_counter));
            assert!(active.windows(2).all(|pair| pair[0] == pair[1]));
            assert!(system.providers.iter().all(|provider| {
                provider.accounts.get(&key).is_some_and(|replica| {
                    replica.status == ReplicaStatus::Active || replica.status == ReplicaStatus::Stale
                })
            }));
            assert!(matches!(
                system.account_operation_state(&key),
                InFlightOperation::Idle
            ));
            assert!(system.login_server.pending.get(&system.uid).is_none());
            assert!(system.login_server.current_verifier(&system.uid).is_some());
            if op == "secupd" {
                assert_ne!(system.login_server.current, before.login_current);
            }
        }
        "auth" => {
            assert_eq!(acknowledgements, 1);
            assert_eq!(decision, Some(true));
            assert!(matches!(
                result,
                PhaseResult::Completed {
                    decision: Some(true),
                    ..
                }
            ));
            assert_eq!(
                system.providers, before.providers,
                "authentication wrote provider state"
            );
            assert_eq!(system.login_server.current, before.login_current);
            assert_eq!(system.login_server.pending, before.login_pending);
            assert_eq!(system.password, before.password);
        }
        "pwdupd" => {
            assert_eq!(decision, None);
            assert!(acknowledgements >= system.qsp);
            assert_eq!(
                system.provider_share_bytes(),
                before
                    .providers
                    .iter()
                    .map(|provider| provider.share(&system.uid).map(|share| share.to_bytes()))
                    .collect::<Vec<_>>()
            );
            let active = system
                .providers
                .iter()
                .filter_map(|provider| provider.identifications.get(&system.uid))
                .filter(|replica| replica.status == ReplicaStatus::Active)
                .collect::<Vec<_>>();
            assert_eq!(active.len(), acknowledgements);
            let previous_counter = before
                .providers
                .iter()
                .filter_map(|provider| provider.identifications.get(&system.uid))
                .map(|replica| replica.current.ctrid)
                .max()
                .expect("setup roots");
            assert!(active.iter().all(|replica| {
                replica.current.ctrid == previous_counter + 1
                    && replica.current.signature.is_some()
                    && replica.tentative_identification.is_none()
            }));
            assert!(active.windows(2).all(|pair| pair[0].current == pair[1].current));
            assert!(system.providers.iter().all(|provider| {
                provider
                    .identifications
                    .get(&system.uid)
                    .is_some_and(|replica| replica.tentative_identification.is_none())
            }));
            assert!(matches!(
                system.identification_operation_state(),
                InFlightOperation::Idle
            ));
            assert_eq!(system.password, system.new_password);
            assert_eq!(system.login_server.current, before.login_current);
            assert_eq!(system.login_server.pending, before.login_pending);
        }
        "sync_ident" => {
            assert_eq!(decision, None);
            assert!(acknowledgements >= system.qsp);
            let recover = recover_index.expect("recoverer");
            let replica = system.providers[recover]
                .identifications
                .get(&system.uid)
                .expect("recovered identification");
            assert_eq!(replica.status, ReplicaStatus::Active);
            assert_eq!(replica.current.ctrid, 1);
            assert_eq!(
                system.providers[recover]
                    .share(&system.uid)
                    .map(|share| share.to_bytes()),
                before.providers[recover]
                    .share(&system.uid)
                    .map(|share| share.to_bytes())
            );
            assert_eq!(system.provider_share_bytes(), {
                before
                    .providers
                    .iter()
                    .map(|provider| provider.share(&system.uid).map(|share| share.to_bytes()))
                    .collect::<Vec<_>>()
            });
        }
        "sync_account" => {
            assert_eq!(decision, None);
            assert!(acknowledgements >= system.qsp);
            let recover = recover_index.expect("recoverer");
            let key = system.any_account_family().expect("recovered account family");
            let replica = system.providers[recover]
                .accounts
                .get(&key)
                .expect("recovered account");
            assert_eq!(replica.status, ReplicaStatus::Active);
            assert!(replica.current.is_some());
            assert_eq!(
                system.provider_share_bytes(),
                before
                    .providers
                    .iter()
                    .map(|provider| provider.share(&system.uid).map(|share| share.to_bytes()))
                    .collect::<Vec<_>>()
            );
            assert_eq!(system.login_server.current, before.login_current);
            assert_eq!(system.login_server.pending, before.login_pending);
        }
        _ => unreachable!("validated RoUpSPA operation"),
    }
}

fn processing_components(local: u128, trace: &ProtocolTrace) -> (u128, u128, u128) {
    let provider = (trace.provider_processing_ns() as u128).min(local);
    let login_server = (trace.login_server_processing_ns() as u128).min(local.saturating_sub(provider));
    let client = local.saturating_sub(provider.saturating_add(login_server));
    (client, provider, login_server)
}

#[allow(clippy::too_many_arguments)]
fn sample(
    kind: &str,
    op: &str,
    nsp: usize,
    tsp: usize,
    qsp: usize,
    unavailable: usize,
    iteration: u64,
    profile: NetProfile,
    config: &Config,
) -> Sample {
    let (mut system, recoverer) = prepare_system(op, nsp, tsp, qsp, unavailable, iteration);
    let before = capture_state(&system);
    if kind == "net_only" {
        let result = execute(&mut system, op, recoverer);
        assert_phase_postconditions(&system, op, recoverer, &result, &before);
        let trace = result.trace().clone();
        let (cost, delivery_bound) = network_cost(&trace, profile, config, iteration + 1);
        black_box(cost);
        let network = cost.total as u128;
        return Sample {
            client: 0,
            provider: 0,
            login_server: 0,
            network,
            total: network,
            network_cost: cost,
            delivery_bound,
            trace,
        };
    }

    let started = Instant::now();
    let result = execute(&mut system, op, recoverer);
    let local = started.elapsed().as_nanos();
    assert_phase_postconditions(&system, op, recoverer, &result, &before);
    let trace = result.trace().clone();
    let (network_cost, delivery_bound) = if kind == "full_net" {
        network_cost(&trace, profile, config, iteration + 1)
    } else {
        let (_, bound) = network_cost(&trace, profile, config, iteration + 1);
        (NetworkCost::default(), bound)
    };
    let network = network_cost.total as u128;
    let (client_processing, provider_processing, login_server_processing) =
        processing_components(local, &trace);
    let (client, provider, login_server, included_processing) = match kind {
        "client" => (client_processing, 0, 0, client_processing),
        "provider" => (0, provider_processing, 0, provider_processing),
        "login_server" => (0, 0, login_server_processing, login_server_processing),
        "full_no_net" | "full_net" => (
            client_processing,
            provider_processing,
            login_server_processing,
            local,
        ),
        _ => unreachable!("validated non-network-only benchmark kind"),
    };
    Sample {
        client,
        provider,
        login_server,
        network,
        total: included_processing.saturating_add(network),
        network_cost,
        delivery_bound,
        trace,
    }
}

#[allow(clippy::too_many_arguments)]
fn write_row(
    output: &mut BufWriter<File>,
    kind: &str,
    op: &str,
    profile_name: &str,
    nsp: usize,
    tsp: usize,
    qsp: usize,
    unavailable: usize,
    config: &Config,
    samples: &[Sample],
) -> std::io::Result<()> {
    let totals: Vec<u128> = samples.iter().map(|sample| sample.total).collect();
    let distribution = stats(totals);
    let client = mean_u128(&samples.iter().map(|sample| sample.client).collect::<Vec<_>>());
    let provider = mean_u128(&samples.iter().map(|sample| sample.provider).collect::<Vec<_>>());
    let login_server = mean_u128(
        &samples
            .iter()
            .map(|sample| sample.login_server)
            .collect::<Vec<_>>(),
    );
    let network = mean_u128(&samples.iter().map(|sample| sample.network).collect::<Vec<_>>());
    let mean_stage = |select: fn(&NetworkCost) -> u64| -> u128 {
        samples
            .iter()
            .map(|sample| select(&sample.network_cost) as u128)
            .sum::<u128>()
            / samples.len() as u128
    };
    let trace = &samples[0].trace;
    let delivery_bound = samples
        .iter()
        .map(|sample| sample.delivery_bound as u128)
        .sum::<u128>()
        / samples.len() as u128;
    writeln!(
        output,
        "roupspa {op} {kind} {profile_name} {nsp} {tsp} {qsp} {unavailable} {delivery_bound} {} {} {client} {provider} {login_server} {network} {} {} {} {} {} {} {} {} {} {} completed {} {} {} {} {} {:.3} {:.3}",
        config.samples,
        config.warmup,
        distribution.mean.round() as u128,
        mean_stage(|cost| cost.identification),
        mean_stage(|cost| cost.account_read),
        mean_stage(|cost| cost.prepare),
        mean_stage(|cost| cost.write),
        mean_stage(|cost| cost.terminal),
        trace.request_bytes(),
        trace.response_bytes(),
        trace.message_count(),
        trace.acknowledgement_count(),
        if config.rng_in_timed { 1 } else { 0 },
        distribution.min,
        distribution.p50,
        distribution.p95,
        distribution.max,
        distribution.mean,
        distribution.stddev,
    )
}

pub fn run(args: Vec<String>) -> std::io::Result<()> {
    let config = parse_args(args);
    let tuples = threshold_tuples(&config);
    let profiles = profiles(&config);
    let mut output = BufWriter::new(File::create(&config.output)?);
    writeln!(output, "{HEADER}")?;

    for (nsp, tsp, qsp) in tuples {
        for op in &config.ops {
            validate_operation_tuple(op, nsp, qsp);
            let row_unavailable = unavailable_for_operation(&config.unavailable, op, nsp, tsp, qsp);
            for kind in &config.kinds {
                let selected_profiles: Vec<NetProfile> = if matches!(kind.as_str(), "net_only" | "full_net") {
                    profiles.clone()
                } else {
                    vec![profiles[0]]
                };
                for profile in selected_profiles {
                    let total = config.warmup + config.samples;
                    let mut timed = Vec::with_capacity(config.samples);
                    for iteration in 0..total {
                        let measured = sample(
                            kind,
                            op,
                            nsp,
                            tsp,
                            qsp,
                            row_unavailable,
                            iteration as u64,
                            profile,
                            &config,
                        );
                        if iteration >= config.warmup {
                            timed.push(measured);
                        }
                    }
                    write_row(
                        &mut output,
                        kind,
                        op,
                        if matches!(kind.as_str(), "net_only" | "full_net") {
                            profile.name
                        } else {
                            "none"
                        },
                        nsp,
                        tsp,
                        qsp,
                        row_unavailable,
                        &config,
                        &timed,
                    )?;
                }
            }
        }
    }
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_bounds_follow_each_protocol_phase() {
        assert_eq!(maximum_unavailable_for_operation("setup", 7, 2, 5), 0);
        assert_eq!(maximum_unavailable_for_operation("auth", 7, 2, 5), 5);
        for op in ["reg", "secupd", "pwdupd", "sync_ident", "sync_account"] {
            assert_eq!(maximum_unavailable_for_operation(op, 7, 2, 5), 2);
        }
        assert_eq!(unavailable_for_operation(&Offline::Count(5), "auth", 7, 2, 5), 5);
        assert_eq!(unavailable_for_operation(&Offline::Max, "auth", 7, 2, 5), 5);
        assert_eq!(unavailable_for_operation(&Offline::Count(5), "setup", 7, 2, 5), 0);
    }

    #[test]
    #[should_panic(expected = "progress bound")]
    fn quorum_phase_rejects_authentication_only_availability() {
        let _ = unavailable_for_operation(&Offline::Count(3), "reg", 7, 2, 5);
    }

    #[test]
    #[should_panic(expected = "qsp < nsp")]
    fn synchronization_rejects_a_full_quorum_tuple() {
        validate_operation_tuple("sync_ident", 3, 3);
    }

    #[test]
    fn processing_split_uses_instrumented_regions_and_client_residual() {
        let mut trace = ProtocolTrace::default();
        trace.record_provider_processing(20);
        trace.record_login_server_processing(30);
        assert_eq!(processing_components(100, &trace), (50, 20, 30));
    }

    #[test]
    fn component_rows_report_only_the_selected_instrumented_role() {
        let config = parse_args(Vec::new());
        let profile = profiles(&config)[0];
        let make = |kind| sample(kind, "reg", 3, 2, 3, 0, 41, profile, &config);

        let client = make("client");
        assert!(client.client > 0);
        assert_eq!(client.provider, 0);
        assert_eq!(client.login_server, 0);
        assert_eq!(client.total, client.client);

        let provider = make("provider");
        assert!(provider.provider > 0);
        assert_eq!(provider.client, 0);
        assert_eq!(provider.login_server, 0);
        assert_eq!(provider.total, provider.provider);

        let login_server = make("login_server");
        assert!(login_server.login_server > 0);
        assert_eq!(login_server.client, 0);
        assert_eq!(login_server.provider, 0);
        assert_eq!(login_server.total, login_server.login_server);

        let full = make("full_no_net");
        assert!(full.client > 0);
        assert!(full.provider > 0);
        assert!(full.login_server > 0);
        assert_eq!(full.total, full.client + full.provider + full.login_server);
    }
}
