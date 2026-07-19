#![allow(clippy::needless_range_loop)]

use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::time::Instant;

use blake3;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar as RScalar};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use pastau_bench::crypto_core;
use pastau_bench::crypto_pastau as pc;
use pastau_bench::protocols::pastau;

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
    assert!(!xs.is_empty(), "cannot compute stats for empty sample set");
    xs.sort_unstable();
    let n = xs.len();
    let min_ns = xs[0];
    let max_ns = xs[n - 1];
    let p50_ns = xs[n / 2];
    let p95_ns = xs[(n * 95) / 100];

    let sum: f64 = xs.iter().map(|&x| x as f64).sum();
    let mean_ns = sum / (n as f64);

    let mut var = 0.0;
    for &x in &xs {
        let d = (x as f64) - mean_ns;
        var += d * d;
    }
    let stddev_ns = if n > 1 {
        (var / ((n - 1) as f64)).sqrt()
    } else {
        0.0
    };

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

fn bench_u128(mut f: impl FnMut() -> u128, warmup: usize, samples: usize) -> Stats {
    for _ in 0..warmup {
        black_box(f());
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(f());
    }
    compute_stats(xs)
}

fn time_call_ns<R>(mut f: impl FnMut() -> R) -> u64 {
    let t0 = Instant::now();
    let out = f();
    black_box(out);
    t0.elapsed().as_nanos() as u64
}

fn median_ns(mut xs: Vec<u64>) -> u64 {
    xs.sort_unstable();
    xs[xs.len() / 2]
}

fn write_header(out: &mut BufWriter<File>) -> std::io::Result<()> {
    writeln!(
        out,
        "scheme kind op rng_in_timed nsp tsp samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns"
    )
}

fn write_row(
    out: &mut BufWriter<File>,
    scheme: &str,
    kind: &str,
    op: &str,
    rng_in_timed: bool,
    nsp: usize,
    tsp: usize,
    warmup: usize,
    st: &Stats,
) -> std::io::Result<()> {
    writeln!(
        out,
        "{} {} {} {} {} {} {} {} {} {} {} {} {:.3} {:.3}",
        scheme,
        kind,
        op,
        if rng_in_timed { 1 } else { 0 },
        nsp,
        tsp,
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
        .map(|x| x.trim().to_ascii_lowercase())
        .collect()
}

fn seed_for(tag: &[u8], nsp: usize, tsp: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&(nsp as u64).to_le_bytes());
    h.update(&(tsp as u64).to_le_bytes());
    let out = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(out.as_bytes());
    seed
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
    let bits = (bytes as u128) * 8u128;
    let bw = bw_bps as u128;
    let ns = (bits * 1_000_000_000u128 + bw - 1) / bw;
    ns as u64
}

fn sample_jitter(rng: &mut impl RngCore, jitter_ns: u64) -> i64 {
    if jitter_ns == 0 {
        return 0;
    }
    let span = (jitter_ns as u128) * 2 + 1;
    let v = (rng.next_u64() as u128) % span;
    (v as i128 - jitter_ns as i128) as i64
}

fn add_signed_ns(base: u64, delta: i64) -> u64 {
    if delta >= 0 {
        base.saturating_add(delta as u64)
    } else {
        base.saturating_sub((-delta) as u64)
    }
}

fn simulate_parallel_phase(
    k: usize,
    req_payload_bytes: usize,
    resp_payload_bytes: usize,
    proc_ns: u64,
    prof: NetProfile,
    rng: &mut impl RngCore,
) -> u64 {
    if k == 0 {
        return 0;
    }

    let req_total = req_payload_bytes + prof.overhead_bytes;
    let resp_total = resp_payload_bytes + prof.overhead_bytes;

    let tx_req = tx_time_ns(req_total, prof.bw_bps);
    let tx_resp = tx_time_ns(resp_total, prof.bw_bps);

    let mut arrivals: Vec<u64> = Vec::with_capacity(k);
    let mut t_uplink_done = 0u64;
    for _ in 0..k {
        t_uplink_done = t_uplink_done.saturating_add(tx_req);
        let j = sample_jitter(rng, prof.jitter_ns);
        let t_arrive = add_signed_ns(t_uplink_done.saturating_add(prof.one_way_ns), j);
        arrivals.push(t_arrive);
    }

    let mut ready: Vec<u64> = Vec::with_capacity(k);
    for &a in &arrivals {
        ready.push(a.saturating_add(proc_ns));
    }

    let mut down_arr: Vec<u64> = Vec::with_capacity(k);
    for &rdy in &ready {
        let j = sample_jitter(rng, prof.jitter_ns);
        let t = add_signed_ns(rdy.saturating_add(tx_resp).saturating_add(prof.one_way_ns), j);
        down_arr.push(t);
    }

    down_arr.sort_unstable();
    let mut t_down_done = 0u64;
    for a in down_arr {
        if t_down_done < a {
            t_down_done = a;
        }
        t_down_done = t_down_done.saturating_add(tx_resp);
    }

    t_down_done
}

fn simulate_one_way_fanout(
    k: usize,
    payload_bytes: usize,
    proc_ns: u64,
    prof: NetProfile,
    rng: &mut impl RngCore,
) -> u64 {
    if k == 0 {
        return 0;
    }

    let total = payload_bytes + prof.overhead_bytes;
    let tx = tx_time_ns(total, prof.bw_bps);

    let mut done = 0u64;
    let mut t_uplink_done = 0u64;
    for _ in 0..k {
        t_uplink_done = t_uplink_done.saturating_add(tx);
        let j = sample_jitter(rng, prof.jitter_ns);
        let arrive = add_signed_ns(t_uplink_done.saturating_add(prof.one_way_ns), j);
        done = done.max(arrive.saturating_add(proc_ns));
    }
    done
}

const SCALAR_BYTES: usize = 32;

const AUTH_REQ_BYTES_PER_SERVER: usize = pastau::UID_LEN + pastau::X_LEN + pastau::TOP_REQ_LEN;
const AUTH_RESP_BYTES_PER_SERVER: usize =
    pastau::TOP_PARTIAL_LEN + (pc::NONCE_LEN + pc::TTG_TOKEN_LEN + pc::TAG_LEN);

const REG_U_TO_IP_BYTES: usize = pastau::UID_LEN + pastau::TOP_REQ_LEN;
const REG_IP_TO_U_BYTES: usize = pastau::TOP_REQ_LEN;
const REG_IP_TO_SERVER_BYTES: usize = pastau::UID_LEN + SCALAR_BYTES;
const REG_U_TO_SERVER_BYTES: usize = pastau::UID_LEN + 32;

fn update_token_req_bytes(nsp: usize) -> usize {
    pastau::UID_LEN + (nsp * pastau::UPDATE_BLOB_LEN) + pastau::TOP_REQ_LEN
}

fn update_push_bytes(nsp: usize) -> usize {
    (nsp * pastau::UPDATE_BLOB_LEN) + pastau::UID_LEN + pc::TTG_TOKEN_LEN
}

#[derive(Clone)]
struct UpdateWire {
    pld3: Vec<u8>,
    tk_pld3: pc::TtgToken,
}

#[derive(Clone)]
struct UpdateIterData {
    rho_old: RScalar,
    rho_new: RScalar,
    rho_token: RScalar,
    nonces_old: Vec<[u8; crypto_core::NONCE_LEN]>,
    nonces_new: Vec<[u8; crypto_core::NONCE_LEN]>,
    nonces_token: Vec<[u8; crypto_core::NONCE_LEN]>,
    update_nonces: Vec<[u8; crypto_core::NONCE_LEN]>,
}

fn make_update_iter_data(fx: &pastau::Fixture, rng: &mut impl RngCore) -> UpdateIterData {
    let rho_old = crypto_core::random_scalar(rng);
    let rho_new = crypto_core::random_scalar(rng);
    let rho_token = crypto_core::random_scalar(rng);

    let mut nonces_old = vec![[0u8; crypto_core::NONCE_LEN]; fx.t];
    let mut nonces_new = vec![[0u8; crypto_core::NONCE_LEN]; fx.t];
    let mut nonces_token = vec![[0u8; crypto_core::NONCE_LEN]; fx.t];
    let mut update_nonces = vec![[0u8; crypto_core::NONCE_LEN]; fx.n];

    for n in nonces_old.iter_mut() {
        rng.fill_bytes(n);
    }
    for n in nonces_new.iter_mut() {
        rng.fill_bytes(n);
    }
    for n in nonces_token.iter_mut() {
        rng.fill_bytes(n);
    }
    for n in update_nonces.iter_mut() {
        rng.fill_bytes(n);
    }

    UpdateIterData {
        rho_old,
        rho_new,
        rho_token,
        nonces_old,
        nonces_new,
        nonces_token,
        update_nonces,
    }
}

fn serialize_update_blob(blob: &pc::CtBlob<{ pastau::UPDATE_PT_LEN }>) -> [u8; pastau::UPDATE_BLOB_LEN] {
    let mut out = [0u8; pastau::UPDATE_BLOB_LEN];
    let mut off = 0usize;
    out[off..off + pc::NONCE_LEN].copy_from_slice(&blob.nonce);
    off += pc::NONCE_LEN;
    out[off..off + pastau::UPDATE_PT_LEN].copy_from_slice(&blob.ct);
    off += pastau::UPDATE_PT_LEN;
    out[off..off + pc::TAG_LEN].copy_from_slice(&blob.tag);
    out
}

fn derive_h_from_responses(
    password: &[u8],
    rho: RScalar,
    ids: &[u32],
    resps: &[pastau::ServerResponse],
) -> Option<[u8; 32]> {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    let lambdas = crypto_core::lagrange_coeffs_at_zero(&sorted);

    let mut partials = Vec::with_capacity(sorted.len());
    for &sid in &sorted {
        let r = resps.iter().find(|r| r.server_id == sid)?;
        let pt = CompressedRistretto(r.z_i).decompress()?;
        partials.push(pt);
    }

    Some(crypto_core::toprf_client_eval_from_partials(
        password, rho, &partials, &lambdas,
    ))
}

fn derive_all_hi(h: &[u8; 32], nsp: usize) -> Vec<[u8; 32]> {
    (1..=nsp as u32).map(|sid| pc::hash_hi(h, sid)).collect()
}

fn build_update_wire_and_client_ns(
    fx: &pastau::Fixture,
    new_password: &[u8],
    rng_in_timed: bool,
    it: &UpdateIterData,
    rng_client: &mut ChaCha20Rng,
) -> Option<(u128, UpdateWire)> {
    let mut client_ns: u128 = 0;

    let t0 = Instant::now();
    let (st_old, creq_old) = if rng_in_timed {
        pastau::request(fx.c, &fx.password, fx.x, &fx.t_set, rng_client)
    } else {
        pastau::request_with_rho(fx.c, &fx.password, fx.x, &fx.t_set, it.rho_old)
    };
    client_ns += t0.elapsed().as_nanos();

    let mut resps_old = Vec::with_capacity(fx.t);
    for (j, &sid) in fx.t_set.iter().enumerate() {
        let srv = &fx.servers[(sid - 1) as usize];
        let resp = pastau::respond_with_nonce(srv, fx.c, fx.x, &creq_old.req, &it.nonces_old[j])?;
        resps_old.push(resp);
    }

    let t0 = Instant::now();
    let h_old = derive_h_from_responses(&fx.password, st_old.rho, &fx.t_set, &resps_old)?;
    let old_hi = derive_all_hi(&h_old, fx.n);
    client_ns += t0.elapsed().as_nanos();

    let t0 = Instant::now();
    let (st_new, creq_new) = if rng_in_timed {
        pastau::request(fx.c, new_password, fx.x, &fx.t_set, rng_client)
    } else {
        pastau::request_with_rho(fx.c, new_password, fx.x, &fx.t_set, it.rho_new)
    };
    client_ns += t0.elapsed().as_nanos();

    let mut resps_new = Vec::with_capacity(fx.t);
    for (j, &sid) in fx.t_set.iter().enumerate() {
        let srv = &fx.servers[(sid - 1) as usize];
        let resp = pastau::respond_with_nonce(srv, fx.c, fx.x, &creq_new.req, &it.nonces_new[j])?;
        resps_new.push(resp);
    }

    let t0 = Instant::now();
    let h_new = derive_h_from_responses(new_password, st_new.rho, &fx.t_set, &resps_new)?;
    let new_hi = derive_all_hi(&h_new, fx.n);
    client_ns += t0.elapsed().as_nanos();

    let aad: [u8; 0] = [];
    let t0 = Instant::now();
    let mut payload_body = Vec::with_capacity(fx.n * pastau::UPDATE_BLOB_LEN);
    for i in 0..fx.n {
        let mut pt = [0u8; pastau::UPDATE_PT_LEN];
        pt[0..32].copy_from_slice(&old_hi[i]);
        pt[32..64].copy_from_slice(&new_hi[i]);

        let blob = if rng_in_timed {
            pc::xchacha_encrypt_detached::<{ pastau::UPDATE_PT_LEN }>(&old_hi[i], &aad, &pt, rng_client)
        } else {
            pc::xchacha_encrypt_detached_with_nonce::<{ pastau::UPDATE_PT_LEN }>(
                &old_hi[i],
                &aad,
                &pt,
                &it.update_nonces[i],
            )
        };
        payload_body.extend_from_slice(&serialize_update_blob(&blob));
    }

    let mut pld3 = Vec::with_capacity(payload_body.len() + pastau::UID_LEN);
    pld3.extend_from_slice(&payload_body);
    pld3.extend_from_slice(&fx.c.0);
    client_ns += t0.elapsed().as_nanos();

    let t0 = Instant::now();
    let rho_token = if rng_in_timed {
        crypto_core::random_scalar(rng_client)
    } else {
        it.rho_token
    };
    let req_token = pc::toprf_encode(&fx.password, rho_token).compress().to_bytes();
    let st_token = pastau::ClientState {
        c: fx.c,
        password: fx.password.clone(),
        rho: rho_token,
        t_set: fx.t_set.clone(),
    };
    client_ns += t0.elapsed().as_nanos();

    let mut resps_token = Vec::with_capacity(fx.t);
    for (j, &sid) in fx.t_set.iter().enumerate() {
        let srv = &fx.servers[(sid - 1) as usize];
        let resp = pastau::respond_var_payload_with_nonce(
            srv,
            fx.c,
            &payload_body,
            &req_token,
            &it.nonces_token[j],
        )?;
        resps_token.push(resp);
    }

    let t0 = Instant::now();
    let tk_pld3 = pastau::finalize(&st_token, &resps_token)?;
    let ok = pc::ttg_verify(&fx.vk, &pld3, &tk_pld3);
    if !ok {
        return None;
    }
    client_ns += t0.elapsed().as_nanos();

    Some((client_ns, UpdateWire { pld3, tk_pld3 }))
}

fn auth_client_ns_and_token(
    fx: &pastau::Fixture,
    rng_in_timed: bool,
    rng_it: &mut ChaCha20Rng,
    rng_req: &mut ChaCha20Rng,
) -> Option<(u128, pc::TtgToken)> {
    let it = pastau::make_iter_data(fx, rng_it);

    let t0 = Instant::now();
    let (st_client, creq) = if rng_in_timed {
        pastau::request(fx.c, &fx.password, fx.x, &fx.t_set, rng_req)
    } else {
        pastau::request_with_rho(fx.c, &fx.password, fx.x, &fx.t_set, it.rho)
    };
    let t_req = t0.elapsed();

    let mut resps = Vec::with_capacity(fx.t);
    for (j, &sid) in fx.t_set.iter().enumerate() {
        let srv = &fx.servers[(sid - 1) as usize];
        let resp = pastau::respond_with_nonce(srv, fx.c, fx.x, &creq.req, &it.nonces[j])?;
        resps.push(resp);
    }
    black_box(&resps);

    let t0 = Instant::now();
    let tk = pastau::finalize(&st_client, &resps)?;
    let ok = pastau::verify(&fx.vk, fx.c, fx.x, &tk);
    if !ok {
        return None;
    }
    let t_fin_verify = t0.elapsed();

    Some(((t_req + t_fin_verify).as_nanos(), tk))
}

#[derive(Clone, Copy, Debug)]
struct ServerProcP50 {
    auth_respond_ns: u64,
    reg_store_ns: u64,
    update_respond_ns: u64,
    update_handle_ns: u64,
}

fn measure_server_procs_p50(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
) -> ServerProcP50 {
    let fx = pastau::make_fixture(nsp, tsp);
    let srv = &fx.servers[0];

    let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/proc/it", nsp, tsp));
    let it = pastau::make_iter_data(&fx, &mut rng);
    let req_bytes = it.req;

    let mut rng_resp = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/proc/auth_respond_rng", nsp, tsp));
    for _ in 0..warmup {
        let out = if rng_in_timed {
            pastau::respond(srv, fx.c, fx.x, &req_bytes, &mut rng_resp)
        } else {
            pastau::respond_with_nonce(srv, fx.c, fx.x, &req_bytes, &it.nonces[0])
        };
        black_box(out);
    }
    let mut xs = Vec::with_capacity(samples);
    for s in 0..samples {
        xs.push(time_call_ns(|| {
            let out = if rng_in_timed {
                pastau::respond(srv, fx.c, fx.x, &req_bytes, &mut rng_resp)
            } else {
                pastau::respond_with_nonce(srv, fx.c, fx.x, &req_bytes, &it.nonces[0])
            };
            black_box((s, out))
        }));
    }
    let auth_respond_ns = median_ns(xs);

    let msg = {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/proc/reg_store_msg", nsp, tsp));
        pastau::registration(nsp, tsp, &fx.password, &mut rng).msgs[0].clone()
    };
    let mut srv2 = pastau::PastauServer::new(1, fx.servers[0].ttg_share);
    for _ in 0..warmup {
        srv2.store(fx.c, &msg);
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| {
            srv2.store(fx.c, &msg);
        }));
    }
    let reg_store_ns = median_ns(xs);

    let new_password = b"new correct horse battery staple".to_vec();
    let mut rng_upd_it = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/proc/update_it", nsp, tsp));
    let upd_it = make_update_iter_data(&fx, &mut rng_upd_it);
    let mut rng_upd_client = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/proc/update_client", nsp, tsp));
    let (_, wire) =
        build_update_wire_and_client_ns(&fx, &new_password, rng_in_timed, &upd_it, &mut rng_upd_client)
            .expect("fixture should build update wire");
    let payload_body = &wire.pld3[..wire.pld3.len() - pastau::UID_LEN];

    let rho = crypto_core::random_scalar(&mut rng_upd_it);
    let req_update = pc::toprf_encode(&fx.password, rho).compress().to_bytes();
    let update_nonce = upd_it.nonces_token[0];
    let mut rng_update_resp =
        ChaCha20Rng::from_seed(seed_for(b"bench_pastau/proc/update_respond_rng", nsp, tsp));
    for _ in 0..warmup {
        let out = if rng_in_timed {
            pastau::respond_var_payload(srv, fx.c, payload_body, &req_update, &mut rng_update_resp)
        } else {
            pastau::respond_var_payload_with_nonce(srv, fx.c, payload_body, &req_update, &update_nonce)
        };
        black_box(out);
    }
    let mut xs = Vec::with_capacity(samples);
    for s in 0..samples {
        xs.push(time_call_ns(|| {
            let out = if rng_in_timed {
                pastau::respond_var_payload(srv, fx.c, payload_body, &req_update, &mut rng_update_resp)
            } else {
                pastau::respond_var_payload_with_nonce(srv, fx.c, payload_body, &req_update, &update_nonce)
            };
            black_box((s, out))
        }));
    }
    let update_respond_ns = median_ns(xs);

    let base_srv = fx.servers[0].clone();
    for _ in 0..warmup {
        let mut srv_tmp = base_srv.clone();
        let ok = pastau::password_update_handle(&mut srv_tmp, &fx.vk, &wire.pld3, &wire.tk_pld3);
        black_box(ok);
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        let mut srv_tmp = base_srv.clone();
        let t0 = Instant::now();
        let ok = pastau::password_update_handle(&mut srv_tmp, &fx.vk, &wire.pld3, &wire.tk_pld3);
        let ns = t0.elapsed().as_nanos() as u64;
        black_box(ok);
        xs.push(ns);
    }
    let update_handle_ns = median_ns(xs);

    ServerProcP50 {
        auth_respond_ns,
        reg_store_ns,
        update_respond_ns,
        update_handle_ns,
    }
}

fn bench_client_proto(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "pastau";
    let fx = pastau::make_fixture(nsp, tsp);

    {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/proto/setup_rng", nsp, tsp));
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = pastau::global_setup(128, nsp, tsp, &mut rng);
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "proto", "setup", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/proto/reg_rng", nsp, tsp));
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = pastau::registration(nsp, tsp, &fx.password, &mut rng);
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "proto", "reg", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    {
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/proto/auth_it", nsp, tsp));
        let mut rng_req = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/proto/auth_req_rng", nsp, tsp));
        let st = bench_u128(
            || {
                let (ns, tk) = auth_client_ns_and_token(&fx, rng_in_timed, &mut rng_it, &mut rng_req)
                    .expect("fixture auth should succeed");
                black_box(tk);
                ns
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "proto", "auth", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    {
        let new_password = b"new correct horse battery staple".to_vec();
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/proto/update_it", nsp, tsp));
        let mut rng_client =
            ChaCha20Rng::from_seed(seed_for(b"bench_pastau/proto/update_client_rng", nsp, tsp));
        let st = bench_u128(
            || {
                let it = make_update_iter_data(&fx, &mut rng_it);
                let (ns, wire) =
                    build_update_wire_and_client_ns(&fx, &new_password, rng_in_timed, &it, &mut rng_client)
                        .expect("fixture update should succeed");
                black_box(wire);
                ns
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "proto",
            "update",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    Ok(())
}

fn bench_server_phases(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "pastau";
    let fx = pastau::make_fixture(nsp, tsp);
    let srv0 = &fx.servers[0];

    {
        let msg = {
            let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/sp/reg_store_msg", nsp, tsp));
            pastau::registration(nsp, tsp, &fx.password, &mut rng).msgs[0].clone()
        };
        let mut srv = pastau::PastauServer::new(1, fx.servers[0].ttg_share);
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                srv.store(fx.c, &msg);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "sp",
            "reg_store",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let ok = srv0.has_record(fx.c);
                black_box(ok);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "sp",
            "auth_db_get",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/sp/auth_respond_it", nsp, tsp));
        let it = pastau::make_iter_data(&fx, &mut rng_it);
        let req_bytes = it.req;
        let mut rng_resp = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/sp/auth_respond_rng", nsp, tsp));

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = if rng_in_timed {
                    pastau::respond(srv0, fx.c, fx.x, &req_bytes, &mut rng_resp)
                } else {
                    pastau::respond_with_nonce(srv0, fx.c, fx.x, &req_bytes, &it.nonces[0])
                };
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "sp",
            "auth_respond",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let new_password = b"new correct horse battery staple".to_vec();
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/sp/update_wire_it", nsp, tsp));
        let upd_it = make_update_iter_data(&fx, &mut rng_it);
        let mut rng_client =
            ChaCha20Rng::from_seed(seed_for(b"bench_pastau/sp/update_wire_client", nsp, tsp));
        let (_, wire) =
            build_update_wire_and_client_ns(&fx, &new_password, rng_in_timed, &upd_it, &mut rng_client)
                .expect("fixture update should build");

        let payload_body = &wire.pld3[..wire.pld3.len() - pastau::UID_LEN];
        let rho = crypto_core::random_scalar(&mut rng_it);
        let req = pc::toprf_encode(&fx.password, rho).compress().to_bytes();
        let nonce = upd_it.nonces_token[0];
        let mut rng_resp = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/sp/update_respond_rng", nsp, tsp));

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = if rng_in_timed {
                    pastau::respond_var_payload(srv0, fx.c, payload_body, &req, &mut rng_resp)
                } else {
                    pastau::respond_var_payload_with_nonce(srv0, fx.c, payload_body, &req, &nonce)
                };
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "sp",
            "update_respond",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let new_password = b"new correct horse battery staple".to_vec();
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/sp/update_handle_it", nsp, tsp));
        let upd_it = make_update_iter_data(&fx, &mut rng_it);
        let mut rng_client =
            ChaCha20Rng::from_seed(seed_for(b"bench_pastau/sp/update_handle_client", nsp, tsp));
        let (_, wire) =
            build_update_wire_and_client_ns(&fx, &new_password, rng_in_timed, &upd_it, &mut rng_client)
                .expect("fixture update should build");

        let base_srv = fx.servers[0].clone();
        let st = bench_u128(
            || {
                let mut srv = base_srv.clone();
                let t0 = Instant::now();
                let ok = pastau::password_update_handle(&mut srv, &fx.vk, &wire.pld3, &wire.tk_pld3);
                black_box(ok);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "sp",
            "update_handle",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    Ok(())
}

fn bench_primitives_constant(
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "pastau";
    let nsp = 0usize;
    let tsp = 0usize;
    let fx = pastau::make_fixture(3, 2);

    {
        let pwd = fx.password.clone();
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let p = crypto_core::hash_to_point(&pwd);
                black_box(p);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "top_hash_to_point",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let pwd = fx.password.clone();
        let rho = RScalar::from(7u64);
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let req = pc::toprf_encode(&pwd, rho);
                black_box(req.compress());
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "top_encode",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let pwd = fx.password.clone();
        let rho = RScalar::from(7u64);
        let req = pc::toprf_encode(&pwd, rho);
        let share = fx.servers[0].get_record(fx.c).unwrap().k_i;
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let z = pc::toprf_eval_share(share, &req);
                black_box(z.compress());
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "top_eval_share",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let h = [42u8; 32];
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = pc::hash_hi(&h, 1);
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "hash_hi_one",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let key = [7u8; 32];
        let pt = [9u8; pc::TTG_TOKEN_LEN];
        let aad: [u8; 0] = [];
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/prim/aead_sig_enc_rng", 0, 0));
        let nonce = [3u8; crypto_core::NONCE_LEN];

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let blob = if rng_in_timed {
                    pc::xchacha_encrypt_detached(&key, &aad, &pt, &mut rng)
                } else {
                    pc::xchacha_encrypt_detached_with_nonce(&key, &aad, &pt, &nonce)
                };
                black_box(blob);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "aead_encrypt_sig",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let key = [7u8; 32];
        let pt = [9u8; pc::TTG_TOKEN_LEN];
        let aad: [u8; 0] = [];
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/prim/aead_sig_dec_rng", 0, 0));
        let blob = pc::xchacha_encrypt_detached(&key, &aad, &pt, &mut rng);

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = pc::xchacha_decrypt_detached(&key, &aad, &blob).unwrap();
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "aead_decrypt_sig",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let key = [7u8; 32];
        let pt = [9u8; pastau::UPDATE_PT_LEN];
        let aad: [u8; 0] = [];
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/prim/aead_update_enc_rng", 0, 0));
        let nonce = [4u8; crypto_core::NONCE_LEN];

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let blob = if rng_in_timed {
                    pc::xchacha_encrypt_detached::<{ pastau::UPDATE_PT_LEN }>(&key, &aad, &pt, &mut rng)
                } else {
                    pc::xchacha_encrypt_detached_with_nonce::<{ pastau::UPDATE_PT_LEN }>(
                        &key, &aad, &pt, &nonce,
                    )
                };
                black_box(blob);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "aead_encrypt_update",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let key = [7u8; 32];
        let pt = [9u8; pastau::UPDATE_PT_LEN];
        let aad: [u8; 0] = [];
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/prim/aead_update_dec_rng", 0, 0));
        let blob = pc::xchacha_encrypt_detached::<{ pastau::UPDATE_PT_LEN }>(&key, &aad, &pt, &mut rng);

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv =
                    pc::xchacha_decrypt_detached::<{ pastau::UPDATE_PT_LEN }>(&key, &aad, &blob).unwrap();
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "aead_decrypt_update",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let msg = [5u8; pastau::X_LEN + pastau::UID_LEN];
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let h = pc::ttg_hash_to_g1(&msg);
                black_box(h);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "ttg_hash_to_g1",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let msg = [5u8; pastau::X_LEN + pastau::UID_LEN];
        let share = fx.servers[0].ttg_share;
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let y = pc::ttg_part_eval(&share, &msg);
                black_box(y);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "ttg_part_eval",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let msg = [5u8; pastau::X_LEN + pastau::UID_LEN];
        let ids: Vec<u32> = vec![1, 2];
        let partials: Vec<_> = (0..2)
            .map(|j| pc::ttg_part_eval(&fx.servers[j].ttg_share, &msg))
            .collect();
        let tk = pc::ttg_combine(&ids, &partials);

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let ok = pc::ttg_verify(&fx.vk, &msg, &tk);
                black_box(ok);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "ttg_verify",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    Ok(())
}

fn bench_primitives_param(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "pastau";
    let fx = pastau::make_fixture(nsp, tsp);

    {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/prim/top_combine_t", nsp, tsp));
        let rho = crypto_core::random_scalar(&mut rng);
        let req = pc::toprf_encode(&fx.password, rho);
        let ids: Vec<u32> = (1..=tsp as u32).collect();
        let lambdas = crypto_core::lagrange_coeffs_at_zero(&ids);
        let mut partials = Vec::with_capacity(tsp);
        for j in 0..tsp {
            let share = fx.servers[j].get_record(fx.c).unwrap().k_i;
            partials.push(pc::toprf_eval_share(share, &req));
        }

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let h = crypto_core::toprf_client_eval_from_partials(&fx.password, rho, &partials, &lambdas);
                black_box(h);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "top_combine_t",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let h = [42u8; 32];
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let all_hi = derive_all_hi(&h, nsp);
                black_box(all_hi);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "hash_hi_all_n",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let old_hi = vec![[7u8; 32]; nsp];
        let new_hi = vec![[8u8; 32]; nsp];
        let aad: [u8; 0] = [];
        let mut rng =
            ChaCha20Rng::from_seed(seed_for(b"bench_pastau/prim/update_payload_encrypt_n", nsp, tsp));
        let mut nonces = vec![[0u8; crypto_core::NONCE_LEN]; nsp];
        for n in nonces.iter_mut() {
            rng.fill_bytes(n);
        }

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let mut payload = Vec::with_capacity(nsp * pastau::UPDATE_BLOB_LEN);
                for i in 0..nsp {
                    let mut pt = [0u8; pastau::UPDATE_PT_LEN];
                    pt[0..32].copy_from_slice(&old_hi[i]);
                    pt[32..64].copy_from_slice(&new_hi[i]);
                    let blob = if rng_in_timed {
                        pc::xchacha_encrypt_detached::<{ pastau::UPDATE_PT_LEN }>(
                            &old_hi[i], &aad, &pt, &mut rng,
                        )
                    } else {
                        pc::xchacha_encrypt_detached_with_nonce::<{ pastau::UPDATE_PT_LEN }>(
                            &old_hi[i], &aad, &pt, &nonces[i],
                        )
                    };
                    payload.extend_from_slice(&serialize_update_blob(&blob));
                }
                black_box(payload);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "update_payload_encrypt_all_n",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let msg = [5u8; pastau::X_LEN + pastau::UID_LEN];
        let ids: Vec<u32> = (1..=tsp as u32).collect();
        let partials: Vec<_> = (0..tsp)
            .map(|j| pc::ttg_part_eval(&fx.servers[j].ttg_share, &msg))
            .collect();

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let tk = pc::ttg_combine(&ids, &partials);
                black_box(tk);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "ttg_combine_t",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    Ok(())
}

fn simulate_reg_network(nsp: usize, store_proc_ns: u64, prof: NetProfile, rng: &mut impl RngCore) -> u64 {
    let step1_2 = simulate_parallel_phase(1, REG_U_TO_IP_BYTES, REG_IP_TO_U_BYTES, 0, prof, rng);

    let step2_servers = simulate_one_way_fanout(nsp, REG_IP_TO_SERVER_BYTES, 0, prof, rng);

    let step3_servers = simulate_one_way_fanout(nsp, REG_U_TO_SERVER_BYTES, store_proc_ns, prof, rng);

    step1_2
        .saturating_add(step2_servers)
        .saturating_add(step3_servers)
}

fn simulate_auth_network(tsp: usize, respond_proc_ns: u64, prof: NetProfile, rng: &mut impl RngCore) -> u64 {
    simulate_parallel_phase(
        tsp,
        AUTH_REQ_BYTES_PER_SERVER,
        AUTH_RESP_BYTES_PER_SERVER,
        respond_proc_ns,
        prof,
        rng,
    )
}

fn simulate_update_network(
    nsp: usize,
    tsp: usize,
    auth_respond_proc_ns: u64,
    update_respond_proc_ns: u64,
    update_handle_proc_ns: u64,
    prof: NetProfile,
    rng: &mut impl RngCore,
) -> u64 {
    let step1 = simulate_parallel_phase(
        tsp,
        AUTH_REQ_BYTES_PER_SERVER,
        AUTH_RESP_BYTES_PER_SERVER,
        auth_respond_proc_ns,
        prof,
        rng,
    );

    let step2 = simulate_parallel_phase(
        tsp,
        AUTH_REQ_BYTES_PER_SERVER,
        AUTH_RESP_BYTES_PER_SERVER,
        auth_respond_proc_ns,
        prof,
        rng,
    );

    let step3 = simulate_parallel_phase(
        tsp,
        update_token_req_bytes(nsp),
        AUTH_RESP_BYTES_PER_SERVER,
        update_respond_proc_ns,
        prof,
        rng,
    );

    let step4 = simulate_one_way_fanout(nsp, update_push_bytes(nsp), update_handle_proc_ns, prof, rng);

    step1
        .saturating_add(step2)
        .saturating_add(step3)
        .saturating_add(step4)
}

fn bench_net(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    prof: NetProfile,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "pastau";
    let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/net", nsp, tsp));

    {
        for _ in 0..warmup {
            let ns = simulate_reg_network(nsp, 0, prof, &mut rng);
            black_box(ns);
        }
        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            xs.push(simulate_reg_network(nsp, 0, prof, &mut rng) as u128);
        }
        let st = compute_stats(xs);
        write_row(
            out,
            scheme,
            "net",
            &format!("reg_{}", prof.name),
            false,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        for _ in 0..warmup {
            let ns = simulate_auth_network(tsp, 0, prof, &mut rng);
            black_box(ns);
        }
        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            xs.push(simulate_auth_network(tsp, 0, prof, &mut rng) as u128);
        }
        let st = compute_stats(xs);
        write_row(
            out,
            scheme,
            "net",
            &format!("auth_{}", prof.name),
            false,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        for _ in 0..warmup {
            let ns = simulate_update_network(nsp, tsp, 0, 0, 0, prof, &mut rng);
            black_box(ns);
        }
        let mut xs = Vec::with_capacity(samples);
        for _ in 0..samples {
            xs.push(simulate_update_network(nsp, tsp, 0, 0, 0, prof, &mut rng) as u128);
        }
        let st = compute_stats(xs);
        write_row(
            out,
            scheme,
            "net",
            &format!("update_{}", prof.name),
            false,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    Ok(())
}

fn bench_full(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    prof: NetProfile,
    proc_warmup: usize,
    proc_samples: usize,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "pastau";

    let proc = measure_server_procs_p50(nsp, tsp, proc_warmup, proc_samples, rng_in_timed);
    let fx = pastau::make_fixture(nsp, tsp);

    {
        let mut rng_reg = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/full/reg_rng", nsp, tsp));
        let mut rng_net = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/full/reg_net", nsp, tsp));
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let reg = pastau::registration(nsp, tsp, &fx.password, &mut rng_reg);
                black_box(reg);
                let cpu_ns = t0.elapsed().as_nanos() as u64;
                let net_ns = simulate_reg_network(nsp, proc.reg_store_ns, prof, &mut rng_net);
                (cpu_ns as u128) + (net_ns as u128)
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "full",
            &format!("reg_{}", prof.name),
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/full/auth_it", nsp, tsp));
        let mut rng_req = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/full/auth_req_rng", nsp, tsp));
        let mut rng_net = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/full/auth_net", nsp, tsp));
        let st = bench_u128(
            || {
                let (client_ns, tk) = auth_client_ns_and_token(&fx, rng_in_timed, &mut rng_it, &mut rng_req)
                    .expect("fixture auth should succeed");
                black_box(tk);
                let net_ns = simulate_auth_network(tsp, proc.auth_respond_ns, prof, &mut rng_net);
                client_ns + (net_ns as u128)
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "full",
            &format!("auth_{}", prof.name),
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let new_password = b"new correct horse battery staple".to_vec();
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/full/update_it", nsp, tsp));
        let mut rng_client =
            ChaCha20Rng::from_seed(seed_for(b"bench_pastau/full/update_client_rng", nsp, tsp));
        let mut rng_net = ChaCha20Rng::from_seed(seed_for(b"bench_pastau/full/update_net", nsp, tsp));

        let st = bench_u128(
            || {
                let it = make_update_iter_data(&fx, &mut rng_it);
                let (client_ns, wire) =
                    build_update_wire_and_client_ns(&fx, &new_password, rng_in_timed, &it, &mut rng_client)
                        .expect("fixture update should succeed");
                black_box(wire);

                let net_ns = simulate_update_network(
                    nsp,
                    tsp,
                    proc.auth_respond_ns,
                    proc.update_respond_ns,
                    proc.update_handle_ns,
                    prof,
                    &mut rng_net,
                );
                client_ns + (net_ns as u128)
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "full",
            &format!("update_{}", prof.name),
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    Ok(())
}

fn usage() -> &'static str {
    "bench_pastau usage:\n\
  cargo run --release --bin bench_pastau -- [flags]\n\
\n\
Flags:\n\
  --kind proto|prim|sp|net|full|all         (default: all)\n\
  --net lan|wan|all                         (default: all; only for kind net/full)\n\
  --nsp 20,40,60                            (default: 20,40,60)\n\
  --tsp 5,10,20                             (absolute; default: empty)\n\
  --tsp-pct 20,50,80                        (percent of nsp; rounded up; clamped; default: 50)\n\
  --sample-size N                           (default: 200)\n\
  --warmup-iters N                          (default: 50)\n\
  --out FILE                                (default: pastau_bench.txt)\n\
  --rng-in-timed                             (include client/server RNG costs in timed CPU regions)\n\
  --lan-rtt-ms / --lan-jitter-ms / --lan-bw-mbps / --overhead-bytes\n\
  --wan-rtt-ms / --wan-jitter-ms / --wan-bw-mbps\n\
  --proc-warmup N / --proc-samples N        (only for kind full; server p50 calibration)\n\
  --help"
}

pub fn run(args: Vec<String>) -> std::io::Result<()> {
    let mut kinds = vec!["all".to_string()];
    let mut nets = vec!["all".to_string()];
    let mut nsp_list = vec![20usize, 40, 60];
    let mut tsp_list: Vec<usize> = Vec::new();
    let mut tsp_pct_list = vec![50u32];
    let mut samples = 200usize;
    let mut warmup = 50usize;
    let mut out_path = "pastau_bench.txt".to_string();
    let mut rng_in_timed = false;

    let mut lan_rtt_ms = 2.0;
    let mut lan_jitter_ms = 0.2;
    let mut lan_bw_mbps = 1000.0;

    let mut wan_rtt_ms = 80.0;
    let mut wan_jitter_ms = 5.0;
    let mut wan_bw_mbps = 100.0;

    let mut overhead_bytes = 40usize;

    let mut proc_warmup = 200usize;
    let mut proc_samples = 400usize;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!("{}", usage());
                return Ok(());
            }
            "--kind" => {
                i += 1;
                kinds = parse_list_string_lower(&args[i]);
            }
            "--net" => {
                i += 1;
                nets = parse_list_string_lower(&args[i]);
            }
            "--nsp" => {
                i += 1;
                nsp_list = parse_list_usize(&args[i]);
            }
            "--tsp" => {
                i += 1;
                tsp_list = parse_list_usize(&args[i]);
                tsp_pct_list.clear();
            }
            "--tsp-pct" => {
                i += 1;
                tsp_pct_list = parse_list_u32(&args[i]);
                tsp_list.clear();
            }
            "--sample-size" => {
                i += 1;
                samples = args[i].parse().expect("bad sample-size");
            }
            "--warmup-iters" => {
                i += 1;
                warmup = args[i].parse().expect("bad warmup-iters");
            }
            "--out" => {
                i += 1;
                out_path = args[i].clone();
            }
            "--rng-in-timed" => {
                rng_in_timed = true;
            }
            "--lan-rtt-ms" => {
                i += 1;
                lan_rtt_ms = args[i].parse().expect("bad lan-rtt-ms");
            }
            "--lan-jitter-ms" => {
                i += 1;
                lan_jitter_ms = args[i].parse().expect("bad lan-jitter-ms");
            }
            "--lan-bw-mbps" => {
                i += 1;
                lan_bw_mbps = args[i].parse().expect("bad lan-bw-mbps");
            }
            "--wan-rtt-ms" => {
                i += 1;
                wan_rtt_ms = args[i].parse().expect("bad wan-rtt-ms");
            }
            "--wan-jitter-ms" => {
                i += 1;
                wan_jitter_ms = args[i].parse().expect("bad wan-jitter-ms");
            }
            "--wan-bw-mbps" => {
                i += 1;
                wan_bw_mbps = args[i].parse().expect("bad wan-bw-mbps");
            }
            "--overhead-bytes" => {
                i += 1;
                overhead_bytes = args[i].parse().expect("bad overhead-bytes");
            }
            "--proc-warmup" => {
                i += 1;
                proc_warmup = args[i].parse().expect("bad proc-warmup");
            }
            "--proc-samples" => {
                i += 1;
                proc_samples = args[i].parse().expect("bad proc-samples");
            }
            other => {
                eprintln!("Unknown flag: {}\n\n{}", other, usage());
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let prof_lan = NetProfile {
        name: "lan",
        one_way_ns: ms_to_ns(lan_rtt_ms / 2.0),
        jitter_ns: ms_to_ns(lan_jitter_ms),
        bw_bps: mbps_to_bps(lan_bw_mbps),
        overhead_bytes,
    };
    let prof_wan = NetProfile {
        name: "wan",
        one_way_ns: ms_to_ns(wan_rtt_ms / 2.0),
        jitter_ns: ms_to_ns(wan_jitter_ms),
        bw_bps: mbps_to_bps(wan_bw_mbps),
        overhead_bytes,
    };

    let mut net_profiles: Vec<NetProfile> = Vec::new();
    if nets.contains(&"all".to_string()) {
        net_profiles.push(prof_lan);
        net_profiles.push(prof_wan);
    } else {
        for n in &nets {
            match n.as_str() {
                "lan" => net_profiles.push(prof_lan),
                "wan" => net_profiles.push(prof_wan),
                _ => {}
            }
        }
    }

    let file = File::create(&out_path)?;
    let mut out = BufWriter::new(file);
    write_header(&mut out)?;

    let kinds_all = kinds.contains(&"all".to_string());
    let want_proto = kinds_all || kinds.contains(&"proto".to_string());
    let want_prim = kinds_all || kinds.contains(&"prim".to_string());
    let want_sp = kinds_all || kinds.contains(&"sp".to_string());
    let want_net = kinds_all || kinds.contains(&"net".to_string());
    let want_full = kinds_all || kinds.contains(&"full".to_string());

    let mut prim_constants_done = false;

    for &nsp in &nsp_list {
        let mut tsps: Vec<usize> = Vec::new();
        tsps.extend(tsp_list.iter().copied().filter(|&t| t >= 1 && t <= nsp));
        for pct in &tsp_pct_list {
            let mut t = ((nsp as u64) * (*pct as u64) + 99) / 100;
            if t < 1 {
                t = 1;
            }
            if t > nsp as u64 {
                t = nsp as u64;
            }
            tsps.push(t as usize);
        }
        tsps.sort_unstable();
        tsps.dedup();

        for &tsp in &tsps {
            if want_proto {
                bench_client_proto(nsp, tsp, warmup, samples, rng_in_timed, &mut out)?;
            }
            if want_sp {
                bench_server_phases(nsp, tsp, warmup, samples, rng_in_timed, &mut out)?;
            }
            if want_prim {
                if !prim_constants_done {
                    bench_primitives_constant(warmup, samples, rng_in_timed, &mut out)?;
                    prim_constants_done = true;
                }
                bench_primitives_param(nsp, tsp, warmup, samples, rng_in_timed, &mut out)?;
            }
            if want_net {
                for prof in &net_profiles {
                    bench_net(nsp, tsp, warmup, samples, *prof, &mut out)?;
                }
            }
            if want_full {
                for prof in &net_profiles {
                    bench_full(
                        nsp,
                        tsp,
                        warmup,
                        samples,
                        rng_in_timed,
                        *prof,
                        proc_warmup,
                        proc_samples,
                        &mut out,
                    )?;
                }
            }
        }
    }

    out.flush()?;
    eprintln!("wrote {}", out_path);
    Ok(())
}
