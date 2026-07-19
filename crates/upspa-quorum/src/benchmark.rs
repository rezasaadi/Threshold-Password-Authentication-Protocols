use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::time::Instant;

use upspa_abd_benchmark::protocols::upspa_abd as abd;

#[derive(Clone, Debug)]
struct Stats {
    n: usize,
    min_ns: u128,
    p50_ns: u128,
    p95_ns: u128,
    max_ns: u128,
    mean_ns: f64,
    stddev_ns: f64,
}

fn compute_stats(mut xs: Vec<u128>) -> Stats {
    assert!(!xs.is_empty(), "cannot compute stats over an empty sample set");
    xs.sort_unstable();
    let n = xs.len();
    let min_ns = xs[0];
    let max_ns = xs[n - 1];
    let p50_ns = xs[n / 2];
    let p95_idx = ((n - 1) * 95) / 100;
    let p95_ns = xs[p95_idx];
    let sum: f64 = xs.iter().map(|&x| x as f64).sum();
    let mean_ns = sum / n as f64;
    let mut var = 0.0;
    for &x in &xs {
        let d = x as f64 - mean_ns;
        var += d * d;
    }
    let stddev_ns = if n > 1 { (var / (n - 1) as f64).sqrt() } else { 0.0 };
    Stats {
        n,
        min_ns,
        p50_ns,
        p95_ns,
        max_ns,
        mean_ns,
        stddev_ns,
    }
}

fn write_header(out: &mut BufWriter<File>) -> std::io::Result<()> {
    writeln!(
        out,
        "scheme kind op net_profile nsp tsp qsp unavailable samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns"
    )
}

fn write_row(
    out: &mut BufWriter<File>,
    kind: &str,
    op: &str,
    net_profile: &str,
    nsp: usize,
    tsp: usize,
    unavailable: usize,
    warmup: usize,
    st: &Stats,
) -> std::io::Result<()> {
    writeln!(
        out,
        "upspa_abd {} {} {} {} {} {} {} {} {} {} {} {} {} {:.3} {:.3}",
        kind,
        op,
        net_profile,
        nsp,
        tsp,
        abd::quorum_size(nsp, tsp),
        unavailable,
        st.n,
        warmup,
        st.min_ns,
        st.p50_ns,
        st.p95_ns,
        st.max_ns,
        st.mean_ns,
        st.stddev_ns
    )
}

fn parse_list_usize(s: &str) -> Vec<usize> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().parse::<usize>().expect("bad usize list element"))
        .collect()
}

fn parse_list_u32(s: &str) -> Vec<u32> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().parse::<u32>().expect("bad u32 list element"))
        .collect()
}

fn parse_list_string_lower(s: &str) -> Vec<String> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().to_ascii_lowercase().replace('-', "_"))
        .collect()
}

fn time_call_ns<R>(mut f: impl FnMut() -> R) -> u128 {
    let t0 = Instant::now();
    let out = f();
    black_box(out);
    t0.elapsed().as_nanos()
}

#[derive(Clone, Copy)]
struct NetProfile {
    name: &'static str,
    one_way_ns: u64,
    jitter_ns: u64,
    bw_bps: u64,
    overhead_bytes: usize,
}

fn ms_to_ns(ms: f64) -> u64 {
    if ms <= 0.0 {
        0
    } else {
        (ms * 1_000_000.0).round() as u64
    }
}

fn mbps_to_bps(mbps: f64) -> u64 {
    if mbps <= 0.0 {
        0
    } else {
        (mbps * 1_000_000.0).round() as u64
    }
}

fn tx_time_ns(bytes: usize, bw_bps: u64) -> u64 {
    if bw_bps == 0 {
        return 0;
    }
    let bits = bytes as u128 * 8u128;
    let bw = bw_bps as u128;
    ((bits * 1_000_000_000u128 + bw - 1) / bw) as u64
}

fn sample_jitter(rng: &mut impl RngCore, jitter_ns: u64) -> i64 {
    if jitter_ns == 0 {
        return 0;
    }
    let span = jitter_ns as u128 * 2 + 1;
    let v = rng.next_u64() as u128 % span;
    (v as i128 - jitter_ns as i128) as i64
}

fn add_signed_ns(base: u64, delta: i64) -> u64 {
    if delta >= 0 {
        base.saturating_add(delta as u64)
    } else {
        base.saturating_sub((-delta) as u64)
    }
}

fn simulate_parallel_all(
    k: usize,
    req_payload_bytes: usize,
    resp_payload_bytes: usize,
    prof: NetProfile,
    rng: &mut impl RngCore,
) -> u64 {
    simulate_parallel_wait_k(k, k, req_payload_bytes, resp_payload_bytes, prof, rng)
}

fn simulate_parallel_wait_k(
    total: usize,
    wait_for: usize,
    req_payload_bytes: usize,
    resp_payload_bytes: usize,
    prof: NetProfile,
    rng: &mut impl RngCore,
) -> u64 {
    if total == 0 || wait_for == 0 {
        return 0;
    }
    assert!(wait_for <= total);

    let req_total = req_payload_bytes + prof.overhead_bytes;
    let resp_total = resp_payload_bytes + prof.overhead_bytes;
    let tx_req = tx_time_ns(req_total, prof.bw_bps);
    let tx_resp = tx_time_ns(resp_total, prof.bw_bps);

    let mut response_arrivals = Vec::with_capacity(total);
    let mut uplink_done = 0u64;
    for _ in 0..total {
        uplink_done = uplink_done.saturating_add(tx_req);
        let req_arrive = add_signed_ns(
            uplink_done.saturating_add(prof.one_way_ns),
            sample_jitter(rng, prof.jitter_ns),
        );
        let resp_arrive = add_signed_ns(
            req_arrive.saturating_add(tx_resp).saturating_add(prof.one_way_ns),
            sample_jitter(rng, prof.jitter_ns),
        );
        response_arrivals.push(resp_arrive);
    }

    response_arrivals.sort_unstable();
    let mut downlink_done = 0u64;
    for (i, arrival) in response_arrivals.into_iter().enumerate() {
        if i >= wait_for {
            break;
        }
        if downlink_done < arrival {
            downlink_done = arrival;
        }
        downlink_done = downlink_done.saturating_add(tx_resp);
    }
    downlink_done
}

fn single_round(req: usize, resp: usize, prof: NetProfile, rng: &mut impl RngCore) -> u64 {
    simulate_parallel_all(1, req, resp, prof, rng)
}

fn net_for_phase(
    op: &str,
    nsp: usize,
    tsp: usize,
    unavailable: usize,
    prof: NetProfile,
    rng: &mut impl RngCore,
) -> u64 {
    let qsp = abd::quorum_size(nsp, tsp);
    let online = nsp.saturating_sub(unavailable);
    let mut total = 0u64;

    total = total.saturating_add(single_round(abd::MSG_UID_BYTES, abd::MSG_STATUS_BYTES, prof, rng));

    total = total.saturating_add(simulate_parallel_all(
        tsp,
        abd::MSG_TOPRF_REQ_BYTES,
        abd::MSG_TOPRF_RESP_BYTES,
        prof,
        rng,
    ));

    total = total.saturating_add(single_round(
        abd::MSG_CIPHERID_REQ_BYTES,
        abd::MSG_CIPHERID_RESP_BYTES,
        prof,
        rng,
    ));

    match op {
        "reg" => {
            total = total.saturating_add(single_round(
                abd::MSG_CIPHERSP_WRITE_REQ_BYTES,
                abd::MSG_STATUS_BYTES,
                prof,
                rng,
            ));
            total = total.saturating_add(simulate_parallel_wait_k(
                online,
                qsp,
                abd::MSG_CIPHERSP_WRITE_REQ_BYTES,
                abd::MSG_STATUS_BYTES,
                prof,
                rng,
            ));
            total = total.saturating_add(single_round(
                abd::MSG_LS_REGISTER_REQ_BYTES,
                abd::MSG_STATUS_BYTES,
                prof,
                rng,
            ));
        }
        "secupd" => {
            total = total.saturating_add(simulate_parallel_all(
                tsp,
                abd::MSG_CIPHERSP_REQ_BYTES,
                abd::MSG_CIPHERSP_RESP_BYTES,
                prof,
                rng,
            ));
            total = total.saturating_add(single_round(
                abd::MSG_CIPHERSP_WRITE_REQ_BYTES,
                abd::MSG_STATUS_BYTES,
                prof,
                rng,
            ));
            total = total.saturating_add(simulate_parallel_wait_k(
                online,
                qsp,
                abd::MSG_CIPHERSP_WRITE_REQ_BYTES,
                abd::MSG_STATUS_BYTES,
                prof,
                rng,
            ));
            total = total.saturating_add(single_round(
                abd::MSG_LS_UPDATE_REQ_BYTES,
                abd::MSG_STATUS_BYTES,
                prof,
                rng,
            ));
        }
        "pwdupd" => {
            total = total.saturating_add(simulate_parallel_all(
                tsp,
                abd::MSG_TOPRF_REQ_BYTES,
                abd::MSG_TOPRF_RESP_BYTES,
                prof,
                rng,
            ));
            total = total.saturating_add(single_round(
                abd::MSG_MASTER_WRITE_REQ_BYTES,
                abd::MSG_STATUS_BYTES,
                prof,
                rng,
            ));
            total = total.saturating_add(simulate_parallel_wait_k(
                online,
                qsp,
                abd::MSG_MASTER_WRITE_REQ_BYTES,
                abd::MSG_STATUS_BYTES,
                prof,
                rng,
            ));
        }
        _ => unreachable!("unknown op"),
    }
    total
}

#[derive(Clone, Debug)]
enum OfflineSpec {
    Max,
    Count(usize),
}

impl OfflineSpec {
    fn parse(s: &str) -> Self {
        let s = s.trim().to_ascii_lowercase();
        match s.as_str() {
            "max" | "quorum_max" | "majority_max" => OfflineSpec::Max,
            "none" | "zero" | "0" => OfflineSpec::Count(0),
            _ => OfflineSpec::Count(
                s.parse::<usize>()
                    .expect("bad --offline value; use max, none, or a nonnegative integer"),
            ),
        }
    }
}

#[derive(Clone, Debug)]
struct Config {
    kinds: Vec<String>,
    ops: Vec<String>,
    nsp_list: Vec<usize>,
    tsp_abs: Option<Vec<usize>>,
    tsp_pct: Option<Vec<u32>>,
    sample_size: usize,
    warmup_iters: usize,
    out_path: String,
    net_sel: String,
    lan_rtt_ms: f64,
    lan_jitter_ms: f64,
    lan_bw_mbps: f64,
    wan_rtt_ms: f64,
    wan_jitter_ms: f64,
    wan_bw_mbps: f64,
    overhead_bytes: usize,
    offline: OfflineSpec,
}

fn print_help() {
    println!(
        r#"bench_unified (focused UpSPA ABD-style quorum benchmark)

KINDS
  --kind full-no-net,full-net,quorum-overhead | all
      full-no-net      Whole reg/secupd/pwdupd protocol with real provider state, no artificial net latency.
      full-net         Same local execution plus LAN/WAN message-level network simulation.
      quorum-overhead  Total ABD synchronization overhead per phase: QWrite plus one stale-provider recovery when unavailable > 0.

OPS
  --ops reg,secupd,pwdupd | all
      Applies to full-no-net, full-net, and quorum-overhead. quorum-overhead emits only reg/secupd/pwdupd rows.

CORE FLAGS
  --out FILE                  Output .dat file (default: abd_bench.dat)
  --nsp 20,40,60              Storage-provider counts (default: 20,40,60,80,100)
  --tsp 11,15                 Absolute TOPRF thresholds; must satisfy 1 <= tsp <= nsp
  --tsp-pct 60,80,100         Percent of nsp, rounded up (default: 60,80,100)
  --offline max|none|N        Providers unavailable during the timed phase (default: max)
                              max means nsp-qsp, where qsp=ceil((nsp+tsp)/2).
  --sample-size N             Timed samples per row (default: 200)
  --warmup-iters N            Warmup iterations per row (default: 50)

NETWORK FLAGS (used only by --kind full-net)
  --net lan|wan|all           Network profiles (default: all)
  --lan-rtt-ms X              Default: 0.6
  --lan-jitter-ms Y           Default: 0.05
  --lan-bw-mbps Z             Default: 1000
  --wan-rtt-ms X              Default: 80
  --wan-jitter-ms Y           Default: 5
  --wan-bw-mbps Z             Default: 100
  --overhead-bytes N          Per-message framing overhead (default: 64)

EXAMPLES
  cargo run --release --bin bench_unified -- --kind all --nsp 20,40 --tsp-pct 60,80,100 --offline max
  cargo run --release --bin bench_unified -- --kind full-no-net --ops reg,secupd,pwdupd --sample-size 500
  cargo run --release --bin bench_unified -- --kind full-net --net wan --offline max --nsp 20 --tsp 11
"#
    );
}

fn parse_args(input: Vec<String>) -> Config {
    let mut cfg = Config {
        kinds: vec!["full_no_net".into(), "full_net".into(), "quorum_overhead".into()],
        ops: vec!["reg".into(), "secupd".into(), "pwdupd".into()],
        nsp_list: vec![20, 40, 60, 80, 100],
        tsp_abs: None,
        tsp_pct: Some(vec![60, 80, 100]),
        sample_size: 200,
        warmup_iters: 50,
        out_path: "abd_bench.dat".to_string(),
        net_sel: "all".to_string(),
        lan_rtt_ms: 0.6,
        lan_jitter_ms: 0.05,
        lan_bw_mbps: 1000.0,
        wan_rtt_ms: 80.0,
        wan_jitter_ms: 5.0,
        wan_bw_mbps: 100.0,
        overhead_bytes: 64,
        offline: OfflineSpec::Max,
    };

    let mut args = input.into_iter();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--kind" => {
                let v = args.next().expect("missing --kind value");
                if v.eq_ignore_ascii_case("all") {
                    cfg.kinds = vec!["full_no_net".into(), "full_net".into(), "quorum_overhead".into()];
                } else {
                    cfg.kinds = parse_list_string_lower(&v);
                }
            }
            "--ops" => {
                let v = args.next().expect("missing --ops value");
                if v.eq_ignore_ascii_case("all") {
                    cfg.ops = vec!["reg".into(), "secupd".into(), "pwdupd".into()];
                } else {
                    cfg.ops = parse_list_string_lower(&v);
                }
            }
            "--nsp" => cfg.nsp_list = parse_list_usize(&args.next().expect("missing --nsp value")),
            "--tsp" => {
                cfg.tsp_abs = Some(parse_list_usize(&args.next().expect("missing --tsp value")));
                cfg.tsp_pct = None;
            }
            "--tsp-pct" => {
                cfg.tsp_pct = Some(parse_list_u32(&args.next().expect("missing --tsp-pct value")));
                cfg.tsp_abs = None;
            }
            "--sample-size" => {
                cfg.sample_size = args
                    .next()
                    .expect("missing --sample-size value")
                    .parse()
                    .expect("bad sample size")
            }
            "--warmup-iters" => {
                cfg.warmup_iters = args
                    .next()
                    .expect("missing --warmup-iters value")
                    .parse()
                    .expect("bad warmup")
            }
            "--out" => cfg.out_path = args.next().expect("missing --out value"),
            "--net" => cfg.net_sel = args.next().expect("missing --net value").to_ascii_lowercase(),
            "--lan-rtt-ms" => {
                cfg.lan_rtt_ms = args
                    .next()
                    .expect("missing --lan-rtt-ms value")
                    .parse()
                    .expect("bad LAN RTT")
            }
            "--lan-jitter-ms" => {
                cfg.lan_jitter_ms = args
                    .next()
                    .expect("missing --lan-jitter-ms value")
                    .parse()
                    .expect("bad LAN jitter")
            }
            "--lan-bw-mbps" => {
                cfg.lan_bw_mbps = args
                    .next()
                    .expect("missing --lan-bw-mbps value")
                    .parse()
                    .expect("bad LAN bandwidth")
            }
            "--wan-rtt-ms" => {
                cfg.wan_rtt_ms = args
                    .next()
                    .expect("missing --wan-rtt-ms value")
                    .parse()
                    .expect("bad WAN RTT")
            }
            "--wan-jitter-ms" => {
                cfg.wan_jitter_ms = args
                    .next()
                    .expect("missing --wan-jitter-ms value")
                    .parse()
                    .expect("bad WAN jitter")
            }
            "--wan-bw-mbps" => {
                cfg.wan_bw_mbps = args
                    .next()
                    .expect("missing --wan-bw-mbps value")
                    .parse()
                    .expect("bad WAN bandwidth")
            }
            "--overhead-bytes" => {
                cfg.overhead_bytes = args
                    .next()
                    .expect("missing --overhead-bytes value")
                    .parse()
                    .expect("bad overhead")
            }
            "--offline" | "--unavailable" => {
                cfg.offline = OfflineSpec::parse(&args.next().expect("missing --offline value"))
            }
            "--bench" => {}
            other => panic!("unknown argument: {} (use --help)", other),
        }
    }

    for k in &cfg.kinds {
        match k.as_str() {
            "full_no_net" | "full_net" | "quorum_overhead" | "quorum" => {}
            _ => panic!(
                "unknown --kind '{}'; use full-no-net, full-net, quorum-overhead, or all",
                k
            ),
        }
    }
    for op in &cfg.ops {
        match op.as_str() {
            "reg" | "secupd" | "pwdupd" => {}
            _ => panic!("unknown --ops '{}'; use reg,secupd,pwdupd, or all", op),
        }
    }
    cfg
}

fn tsp_values_for(nsp: usize, cfg: &Config) -> Vec<usize> {
    let mut values = if let Some(abs) = &cfg.tsp_abs {
        abs.iter().copied().collect::<Vec<_>>()
    } else {
        cfg.tsp_pct
            .as_ref()
            .expect("tsp_pct must be set when tsp_abs is not")
            .iter()
            .map(|&p| ((nsp as u128 * p as u128 + 99) / 100) as usize)
            .map(|t| t.clamp(1, nsp))
            .collect::<Vec<_>>()
    };
    values.sort_unstable();
    values.dedup();
    for &t in &values {
        if t == 0 || t > nsp {
            panic!(
                "invalid ABD-style threshold for nsp={}: tsp={} is not allowed; require 1 <= tsp <= nsp",
                nsp, t
            );
        }
        let qsp = abd::quorum_size(nsp, t);
        if qsp < t || qsp > nsp {
            panic!(
                "invalid ABD-style quorum range for nsp={}, tsp={}: qsp={} is not allowed; require tsp <= qsp <= nsp",
                nsp, t, qsp
            );
        }
        let intersection = 2 * qsp - nsp;
        if intersection <= t - 1 {
            panic!(
                "invalid ABD-style quorum for nsp={}, tsp={}: qsp={} gives 2*qsp-nsp={} but requires > tsp-1={}",
                nsp, t, qsp, intersection, t - 1
            );
        }
    }
    values
}

fn effective_unavailable(nsp: usize, tsp: usize, spec: &OfflineSpec) -> usize {
    let qsp = abd::quorum_size(nsp, tsp);
    let executable_max = abd::max_executable_unavailable(nsp, tsp);
    match spec {
        OfflineSpec::Max => executable_max,
        OfflineSpec::Count(x) => {
            if *x > executable_max {
                panic!(
                    "invalid ABD-style unavailability for nsp={}, tsp={}, qsp={}: offline={} leaves only {} online providers; maximum executable offline is {}",
                    nsp, tsp, qsp, x, nsp.saturating_sub(*x), executable_max
                );
            }
            *x
        }
    }
}

fn make_profiles(cfg: &Config) -> Vec<NetProfile> {
    let lan = NetProfile {
        name: "lan",
        one_way_ns: ms_to_ns(cfg.lan_rtt_ms / 2.0),
        jitter_ns: ms_to_ns(cfg.lan_jitter_ms),
        bw_bps: mbps_to_bps(cfg.lan_bw_mbps),
        overhead_bytes: cfg.overhead_bytes,
    };
    let wan = NetProfile {
        name: "wan",
        one_way_ns: ms_to_ns(cfg.wan_rtt_ms / 2.0),
        jitter_ns: ms_to_ns(cfg.wan_jitter_ms),
        bw_bps: mbps_to_bps(cfg.wan_bw_mbps),
        overhead_bytes: cfg.overhead_bytes,
    };
    match cfg.net_sel.as_str() {
        "lan" => vec![lan],
        "wan" => vec![wan],
        "all" => vec![lan, wan],
        other => panic!("bad --net '{}'; use lan, wan, or all", other),
    }
}

fn make_system_for_op(op: &str, nsp: usize, tsp: usize, iter: u64) -> abd::System {
    let seed = abd::seed_for(b"bench/upspa-abd/system", nsp, tsp, iter);
    let mut sys = abd::System::new(nsp, tsp, seed);
    if op == "secupd" {
        let seed_reg = abd::seed_for(b"bench/upspa-abd/pre-register", nsp, tsp, iter);
        let mut rng = ChaCha20Rng::from_seed(seed_reg);
        sys.force_registered_all(&mut rng)
            .expect("pre-registration must succeed");
    }
    sys
}

fn run_phase(sys: &mut abd::System, op: &str, rng: &mut ChaCha20Rng) -> Result<[u8; 32], abd::PhaseError> {
    match op {
        "reg" => sys.phase_registration(rng),
        "secupd" => sys.phase_secret_update(rng),
        "pwdupd" => sys.phase_password_update(rng),
        _ => unreachable!("unknown phase op"),
    }
}

fn bench_full_no_net(
    out: &mut BufWriter<File>,
    op: &str,
    nsp: usize,
    tsp: usize,
    unavailable: usize,
    warmup: usize,
    samples: usize,
) -> std::io::Result<()> {
    let total_iters = warmup + samples;
    let mut xs = Vec::with_capacity(samples);
    for iter in 0..total_iters {
        let mut sys = make_system_for_op(op, nsp, tsp, iter as u64);
        sys.set_rotating_unavailable(unavailable, iter);
        let seed = abd::seed_for(b"bench/upspa-abd/full-no-net/rng", nsp, tsp, iter as u64);
        let mut rng = ChaCha20Rng::from_seed(seed);
        let elapsed = time_call_ns(|| run_phase(&mut sys, op, &mut rng).expect("phase must succeed"));
        if iter >= warmup {
            xs.push(elapsed);
        }
    }
    let st = compute_stats(xs);
    write_row(out, "full_no_net", op, "none", nsp, tsp, unavailable, warmup, &st)
}

fn bench_full_net(
    out: &mut BufWriter<File>,
    op: &str,
    nsp: usize,
    tsp: usize,
    unavailable: usize,
    prof: NetProfile,
    warmup: usize,
    samples: usize,
) -> std::io::Result<()> {
    let total_iters = warmup + samples;
    let mut xs = Vec::with_capacity(samples);
    for iter in 0..total_iters {
        let mut sys = make_system_for_op(op, nsp, tsp, iter as u64);
        sys.set_rotating_unavailable(unavailable, iter);
        let seed = abd::seed_for(b"bench/upspa-abd/full-net/rng", nsp, tsp, iter as u64);
        let mut rng = ChaCha20Rng::from_seed(seed);
        let local = time_call_ns(|| run_phase(&mut sys, op, &mut rng).expect("phase must succeed"));
        let net_seed = abd::seed_for(b"bench/upspa-abd/full-net/net", nsp, tsp, iter as u64);
        let mut net_rng = ChaCha20Rng::from_seed(net_seed);
        let net = net_for_phase(op, nsp, tsp, unavailable, prof, &mut net_rng) as u128;
        if iter >= warmup {
            xs.push(local + net);
        }
    }
    let st = compute_stats(xs);
    write_row(out, "full_net", op, prof.name, nsp, tsp, unavailable, warmup, &st)
}

fn bench_quorum_overhead(
    out: &mut BufWriter<File>,
    op: &str,
    nsp: usize,
    tsp: usize,
    unavailable: usize,
    warmup: usize,
    samples: usize,
) -> std::io::Result<()> {
    let total_iters = warmup + samples;
    let mut xs = Vec::with_capacity(samples);
    for iter in 0..total_iters {
        let mut sys = abd::System::new(
            nsp,
            tsp,
            abd::seed_for(b"bench/upspa-abd/quorum-total/system", nsp, tsp, iter as u64),
        );
        let mut rng = ChaCha20Rng::from_seed(abd::seed_for(
            b"bench/upspa-abd/quorum-total/rng",
            nsp,
            tsp,
            iter as u64,
        ));
        let recover_idx = iter % nsp;
        let mut elapsed = 0u128;

        match op {
            "reg" => {
                sys.set_rotating_unavailable(unavailable, iter);
                let (suid, blob, ctr) = sys.make_synthetic_csp_payload(&mut rng, 0);
                elapsed = elapsed.saturating_add(time_call_ns(|| {
                    let sig = sys.sign_csp_write(&suid, &blob, ctr);
                    sys.qwrite_csp_register(suid, blob.clone(), ctr, &sig)
                        .expect("registration signed QWrite must succeed")
                }));
                if unavailable > 0 {
                    sys.providers[recover_idx].online = true;
                    elapsed = elapsed.saturating_add(time_call_ns(|| {
                        sys.recover_csp_for_provider(recover_idx, suid)
                            .expect("registration ciphersp recovery must succeed")
                    }));
                }
            }
            "secupd" => {
                sys.install_synthetic_csp_all(&mut rng, 0);
                let suid = sys.any_suid().expect("synthetic suid exists");
                sys.set_rotating_unavailable(unavailable, iter);
                let (_unused_suid, blob, ctr) = sys.make_synthetic_csp_payload(&mut rng, 1);
                elapsed = elapsed.saturating_add(time_call_ns(|| {
                    let sig = sys.sign_csp_write(&suid, &blob, ctr);
                    sys.qwrite_csp_update(suid, blob.clone(), ctr, &sig)
                        .expect("secret-update signed QWrite must succeed")
                }));
                if unavailable > 0 {
                    sys.providers[recover_idx].online = true;
                    elapsed = elapsed.saturating_add(time_call_ns(|| {
                        sys.recover_csp_for_provider(recover_idx, suid)
                            .expect("secret-update ciphersp recovery must succeed")
                    }));
                }
            }
            "pwdupd" => {
                sys.set_rotating_unavailable(unavailable, iter);
                let (blob, ctrid, sig) = sys
                    .make_valid_master_update_payload(&mut rng)
                    .expect("valid master payload");
                elapsed = elapsed.saturating_add(time_call_ns(|| {
                    sys.qwrite_master(blob.clone(), ctrid, &sig)
                        .expect("password-update QWrite must succeed")
                }));
                if unavailable > 0 {
                    sys.providers[recover_idx].online = true;
                    elapsed = elapsed.saturating_add(time_call_ns(|| {
                        sys.recover_master_for_provider(recover_idx)
                            .expect("master recovery must succeed")
                    }));
                }
            }
            _ => unreachable!("unknown phase op"),
        }

        if iter >= warmup {
            xs.push(elapsed);
        }
    }
    let st = compute_stats(xs);
    write_row(
        out,
        "quorum_overhead",
        op,
        "none",
        nsp,
        tsp,
        unavailable,
        warmup,
        &st,
    )
}

pub fn run(args: Vec<String>) -> std::io::Result<()> {
    let cfg = parse_args(args);
    let profiles = make_profiles(&cfg);
    let do_full_no_net = cfg.kinds.iter().any(|k| k == "full_no_net");
    let do_full_net = cfg.kinds.iter().any(|k| k == "full_net");
    let do_quorum = cfg.kinds.iter().any(|k| k == "quorum_overhead" || k == "quorum");

    let file = File::create(&cfg.out_path)?;
    let mut out = BufWriter::new(file);
    write_header(&mut out)?;

    for &nsp in &cfg.nsp_list {
        for tsp in tsp_values_for(nsp, &cfg) {
            let unavailable = effective_unavailable(nsp, tsp, &cfg.offline);
            let qsp = abd::quorum_size(nsp, tsp);
            if nsp - unavailable < qsp || nsp - unavailable < tsp {
                panic!(
                    "internal error: unavailable={} leaves too few providers for nsp={}, tsp={}, qsp={}",
                    unavailable, nsp, tsp, qsp
                );
            }

            for op in &cfg.ops {
                if do_full_no_net {
                    bench_full_no_net(
                        &mut out,
                        op,
                        nsp,
                        tsp,
                        unavailable,
                        cfg.warmup_iters,
                        cfg.sample_size,
                    )?;
                }
                if do_full_net {
                    for prof in &profiles {
                        bench_full_net(
                            &mut out,
                            op,
                            nsp,
                            tsp,
                            unavailable,
                            *prof,
                            cfg.warmup_iters,
                            cfg.sample_size,
                        )?;
                    }
                }
            }

            if do_quorum {
                for op in &cfg.ops {
                    bench_quorum_overhead(
                        &mut out,
                        op,
                        nsp,
                        tsp,
                        unavailable,
                        cfg.warmup_iters,
                        cfg.sample_size,
                    )?;
                }
            }
        }
    }
    out.flush()?;
    Ok(())
}
