#![allow(clippy::needless_range_loop)]
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::time::Instant;

use augsso_bench::protocols::augsso;
use augsso_bench::{crypto_augsso as ac, crypto_core};

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
    xs.sort_unstable();
    let n = xs.len();
    let min_ns = xs[0];
    let p50_ns = xs[n / 2];
    let p95_ns = xs[(n * 95) / 100];
    let max_ns = xs[n - 1];

    let sum: u128 = xs.iter().sum();
    let mean_ns = (sum as f64) / (n as f64);

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
        st.stddev_ns,
    )
}

#[derive(Clone, Copy, Debug)]
struct NetProfile {
    name: &'static str,
    one_way_ns: u64,
    jitter_ns: u64,
    bw_bps: u64,
    overhead_bytes: usize,
}

fn mk_profile(
    name: &'static str,
    rtt_ms: f64,
    jitter_ms: f64,
    bw_mbps: f64,
    overhead_bytes: usize,
) -> NetProfile {
    let one_way_ns = ((rtt_ms * 1_000_000.0) / 2.0).round() as u64;
    let jitter_ns = (jitter_ms * 1_000_000.0).round() as u64;
    let bw_bps = (bw_mbps * 1_000_000.0).round() as u64;
    NetProfile {
        name,
        one_way_ns,
        jitter_ns,
        bw_bps,
        overhead_bytes,
    }
}

fn tx_time_ns(bytes: usize, bw_bps: u64) -> u64 {
    let bits = (bytes as u64) * 8;
    let num = bits.saturating_mul(1_000_000_000u64);
    (num + bw_bps - 1) / bw_bps
}

fn sample_jitter_ns(jitter_ns: u64, rng: &mut impl RngCore) -> i64 {
    if jitter_ns == 0 {
        return 0;
    }
    let r = (rng.next_u64() as f64) / (u64::MAX as f64);
    let x = (2.0 * r - 1.0) * (jitter_ns as f64);
    x.round() as i64
}

fn add_signed_ns(t: u64, delta: i64) -> u64 {
    if delta >= 0 {
        t.saturating_add(delta as u64)
    } else {
        t.saturating_sub((-delta) as u64)
    }
}

fn simulate_parallel_phase(
    k: usize,
    req_bytes_per_server: usize,
    resp_bytes_per_server: usize,
    server_proc_ns_p50: u64,
    prof: NetProfile,
    rng: &mut impl RngCore,
) -> u64 {
    if k == 0 {
        return 0;
    }

    let req_bytes = req_bytes_per_server + prof.overhead_bytes;
    let resp_bytes = resp_bytes_per_server + prof.overhead_bytes;

    let tx_req = tx_time_ns(req_bytes, prof.bw_bps);
    let tx_resp = tx_time_ns(resp_bytes, prof.bw_bps);

    let mut server_start_times = Vec::with_capacity(k);
    for i in 0..k {
        let send_done = (i as u64 + 1) * tx_req;
        let jitter = sample_jitter_ns(prof.jitter_ns, rng);
        let arrive = add_signed_ns(send_done.saturating_add(prof.one_way_ns), jitter);
        server_start_times.push(arrive);
    }

    let mut server_done_times = Vec::with_capacity(k);
    for &st in &server_start_times {
        server_done_times.push(st.saturating_add(server_proc_ns_p50));
    }

    server_done_times.sort_unstable();

    let mut client_rx_done = 0u64;
    for (i, &done) in server_done_times.iter().enumerate() {
        let jitter = sample_jitter_ns(prof.jitter_ns, rng);
        let first_bit = add_signed_ns(done.saturating_add(prof.one_way_ns), jitter);

        let start = client_rx_done.max(first_bit);
        let end = start.saturating_add(tx_resp);
        client_rx_done = end;

        black_box(i);
    }

    client_rx_done
}

const AUTH_REQ1_BYTES_PER_SERVER: usize = augsso::PLD_LEN + augsso::BPW_LEN;
const AUTH_RESP1_BYTES_PER_SERVER: usize = augsso::SIGMA_LEN + augsso::CTRES_LEN;

const AUTH_REQ2_BYTES_PER_SERVER: usize = augsso::CTCH_LEN;
const AUTH_RESP2_BYTES_PER_SERVER: usize = augsso::CTTKN_LEN;

const REG_REQ_BYTES_PER_SERVER: usize = augsso::UID_LEN + 32 + ac::PKE_PK_LEN;
const REG_RESP_BYTES_PER_SERVER: usize = 0;

const UPDATE_PKE_PT_LEN: usize = augsso::CH_LEN + augsso::EK_LEN + augsso::SIGMA_LEN;
const UPDATE_CTCH_PT_LEN: usize = augsso::CH_LEN + ac::PKE_PK_LEN;
const UPDATE_REQ1_BYTES_PER_SERVER: usize = augsso::UID_LEN + 2 * augsso::BPW_LEN;
const UPDATE_RESP1_BYTES_PER_SERVER: usize = augsso::SIGMA_LEN
    + ac::PKE_EPHEMERAL_PK_LEN
    + crypto_core::NONCE_LEN
    + UPDATE_PKE_PT_LEN
    + crypto_core::TAG_LEN;
const UPDATE_REQ2_BYTES_PER_SERVER: usize =
    crypto_core::NONCE_LEN + UPDATE_CTCH_PT_LEN + crypto_core::TAG_LEN;
const UPDATE_RESP2_BYTES_PER_SERVER: usize = augsso::SIGMA_LEN;

#[derive(Clone, Debug)]
struct PasswordUpdateClientState {
    old_password: Vec<u8>,
    new_password: Vec<u8>,
    r_old: ac::Scalar,
    r_new: ac::Scalar,
    t_set: Vec<u32>,
    nsp: usize,
}

#[derive(Clone, Debug)]
struct PasswordUpdateRequest {
    client_id: augsso::ClientId,
    bpw_old: [u8; augsso::BPW_LEN],
    bpw_new: [u8; augsso::BPW_LEN],
}

#[derive(Clone, Debug)]
struct PasswordUpdateResponse1 {
    server_id: u32,
    sigma_old_i: [u8; augsso::SIGMA_LEN],
    ct_res: ac::PkeCt<UPDATE_PKE_PT_LEN>,
}

#[derive(Clone, Debug)]
struct PasswordUpdateServerSession {
    server_id: u32,
    client_id: augsso::ClientId,
    bpw_new: [u8; augsso::BPW_LEN],
    ek: [u8; augsso::EK_LEN],
    ch: [u8; augsso::CH_LEN],
}

#[derive(Clone, Debug)]
struct PasswordUpdateClientPhase1 {
    ct_ch: Vec<(u32, crypto_core::CtBlob<UPDATE_CTCH_PT_LEN>)>,
}

#[derive(Clone, Debug)]
struct PasswordUpdateResponse2 {
    server_id: u32,
    sigma_phi_i: [u8; augsso::SIGMA_LEN],
    new_rpk: [u8; ac::PKE_PK_LEN],
}

#[derive(Clone)]
struct PasswordUpdateIterData {
    r_old: ac::Scalar,
    r_new: ac::Scalar,
    respond1_rand: Vec<augsso::Respond1Rand>,
    ctch_nonces: Vec<[u8; crypto_core::NONCE_LEN]>,
}

fn make_password_update_iter_data(fx: &augsso::Fixture, rng: &mut impl RngCore) -> PasswordUpdateIterData {
    let r_old = ac::random_scalar_nonzero(rng);
    let r_new = ac::random_scalar_nonzero(rng);

    let mut respond1_rand = Vec::with_capacity(fx.n);
    let mut ctch_nonces = Vec::with_capacity(fx.n);
    for _ in 0..fx.n {
        let mut ch = [0u8; augsso::CH_LEN];
        let mut ek = [0u8; augsso::EK_LEN];
        let mut pke_eph_sk = [0u8; 32];
        let mut pke_nonce = [0u8; crypto_core::NONCE_LEN];
        let mut ctch_nonce = [0u8; crypto_core::NONCE_LEN];
        rng.fill_bytes(&mut ch);
        rng.fill_bytes(&mut ek);
        rng.fill_bytes(&mut pke_eph_sk);
        rng.fill_bytes(&mut pke_nonce);
        rng.fill_bytes(&mut ctch_nonce);
        respond1_rand.push(augsso::Respond1Rand {
            ch,
            ek,
            pke_eph_sk,
            pke_nonce,
        });
        ctch_nonces.push(ctch_nonce);
    }

    PasswordUpdateIterData {
        r_old,
        r_new,
        respond1_rand,
        ctch_nonces,
    }
}

fn password_update_request_with_r(
    fx: &augsso::Fixture,
    new_password: &[u8],
    r_old: ac::Scalar,
    r_new: ac::Scalar,
) -> (PasswordUpdateClientState, PasswordUpdateRequest) {
    let old_h = ac::hash_to_g1(b"augsso/H_pw/v1", &fx.password);
    let new_h = ac::hash_to_g1(b"augsso/H_pw/v1", new_password);
    let bpw_old = ac::g1_to_bytes(&(old_h * r_old));
    let bpw_new = ac::g1_to_bytes(&(new_h * r_new));

    (
        PasswordUpdateClientState {
            old_password: fx.password.clone(),
            new_password: new_password.to_vec(),
            r_old,
            r_new,
            t_set: fx.t_set.clone(),
            nsp: fx.n,
        },
        PasswordUpdateRequest {
            client_id: fx.c,
            bpw_old,
            bpw_new,
        },
    )
}

fn password_update_request(
    fx: &augsso::Fixture,
    new_password: &[u8],
    rng: &mut impl RngCore,
) -> (PasswordUpdateClientState, PasswordUpdateRequest) {
    let r_old = ac::random_scalar_nonzero(rng);
    let r_new = ac::random_scalar_nonzero(rng);
    password_update_request_with_r(fx, new_password, r_old, r_new)
}

fn password_update_respond1_with_rand(
    srv: &augsso::AugSsoServer,
    req: &PasswordUpdateRequest,
    rand: &augsso::Respond1Rand,
) -> Option<(PasswordUpdateResponse1, PasswordUpdateServerSession)> {
    let rec = srv.get_record(req.client_id)?;
    let bpw_old = ac::g1_from_bytes(&req.bpw_old)?;
    let bpw_new = ac::g1_from_bytes(&req.bpw_new)?;

    let sigma_old_i = ac::g1_to_bytes(&(bpw_old * rec.sk_i));
    let sigma_new_i = ac::g1_to_bytes(&(bpw_new * rec.sk_i));

    let mut pt = [0u8; UPDATE_PKE_PT_LEN];
    pt[0..augsso::CH_LEN].copy_from_slice(&rand.ch);
    pt[augsso::CH_LEN..augsso::CH_LEN + augsso::EK_LEN].copy_from_slice(&rand.ek);
    pt[augsso::CH_LEN + augsso::EK_LEN..].copy_from_slice(&sigma_new_i);

    let aad: [u8; 0] = [];
    let ct_res = ac::pke_enc_with_eph_and_nonce::<UPDATE_PKE_PT_LEN>(
        &rec.rpk,
        &aad,
        &pt,
        &rand.pke_eph_sk,
        &rand.pke_nonce,
    );

    Some((
        PasswordUpdateResponse1 {
            server_id: srv.id,
            sigma_old_i,
            ct_res,
        },
        PasswordUpdateServerSession {
            server_id: srv.id,
            client_id: req.client_id,
            bpw_new: req.bpw_new,
            ek: rand.ek,
            ch: rand.ch,
        },
    ))
}

fn password_update_respond1(
    srv: &augsso::AugSsoServer,
    req: &PasswordUpdateRequest,
    rng: &mut impl RngCore,
) -> Option<(PasswordUpdateResponse1, PasswordUpdateServerSession)> {
    let mut ch = [0u8; augsso::CH_LEN];
    let mut ek = [0u8; augsso::EK_LEN];
    let mut pke_eph_sk = [0u8; 32];
    let mut pke_nonce = [0u8; crypto_core::NONCE_LEN];
    rng.fill_bytes(&mut ch);
    rng.fill_bytes(&mut ek);
    rng.fill_bytes(&mut pke_eph_sk);
    rng.fill_bytes(&mut pke_nonce);
    let rand = augsso::Respond1Rand {
        ch,
        ek,
        pke_eph_sk,
        pke_nonce,
    };
    password_update_respond1_with_rand(srv, req, &rand)
}

fn password_update_client_phase1(
    st: &PasswordUpdateClientState,
    req: &PasswordUpdateRequest,
    resps: &[PasswordUpdateResponse1],
    pk_shares: &[(u32, ac::G2)],
    ctch_nonces: Option<&[[u8; crypto_core::NONCE_LEN]]>,
    rng: &mut impl RngCore,
) -> Option<PasswordUpdateClientPhase1> {
    if resps.len() != st.nsp {
        return None;
    }
    let mut ids: Vec<u32> = resps.iter().map(|r| r.server_id).collect();
    ids.sort_unstable();
    let expected: Vec<u32> = (1..=st.nsp as u32).collect();
    if ids != expected {
        return None;
    }

    let bpw_old = ac::g1_from_bytes(&req.bpw_old)?;
    let bpw_new = ac::g1_from_bytes(&req.bpw_new)?;

    for resp in resps {
        let sigma = ac::g1_from_bytes(&resp.sigma_old_i)?;
        let pk_i = pk_shares
            .iter()
            .find(|(id, _)| *id == resp.server_id)
            .map(|(_, pk)| *pk)?;
        if !ac::pairing_check_g1_g2(&sigma, &bpw_old, &pk_i) {
            return None;
        }
    }

    let mut old_partials = Vec::with_capacity(st.t_set.len());
    for sid in &st.t_set {
        let resp = resps.iter().find(|r| r.server_id == *sid)?;
        old_partials.push(ac::g1_from_bytes(&resp.sigma_old_i)?);
    }
    let r_old_inv = Option::<ac::Scalar>::from(st.r_old.invert())?;
    let sigma_old = ac::combine_g1_at_zero(&st.t_set, &old_partials) * r_old_inv;
    let hpw_old = ac::hash_g1_and_bytes_to_32(b"augsso/hpw/v1", &sigma_old, &st.old_password);
    let old_kp = ac::pke_kg(&hpw_old);

    let aad: [u8; 0] = [];
    let mut decoded = Vec::with_capacity(st.nsp);
    for resp in resps {
        let pt = ac::pke_dec::<UPDATE_PKE_PT_LEN>(&old_kp.sk, &aad, &resp.ct_res).ok()?;
        let mut ch = [0u8; augsso::CH_LEN];
        let mut ek = [0u8; augsso::EK_LEN];
        let mut sigma_new_bytes = [0u8; augsso::SIGMA_LEN];
        ch.copy_from_slice(&pt[0..augsso::CH_LEN]);
        ek.copy_from_slice(&pt[augsso::CH_LEN..augsso::CH_LEN + augsso::EK_LEN]);
        sigma_new_bytes.copy_from_slice(&pt[augsso::CH_LEN + augsso::EK_LEN..]);
        let sigma_new = ac::g1_from_bytes(&sigma_new_bytes)?;
        let pk_i = pk_shares
            .iter()
            .find(|(id, _)| *id == resp.server_id)
            .map(|(_, pk)| *pk)?;
        if !ac::pairing_check_g1_g2(&sigma_new, &bpw_new, &pk_i) {
            return None;
        }
        decoded.push((resp.server_id, ch, ek, sigma_new));
    }

    let mut new_partials = Vec::with_capacity(st.t_set.len());
    for sid in &st.t_set {
        let (_, _, _, sigma_new) = decoded.iter().find(|(id, _, _, _)| id == sid)?;
        new_partials.push(*sigma_new);
    }
    let r_new_inv = Option::<ac::Scalar>::from(st.r_new.invert())?;
    let sigma_new = ac::combine_g1_at_zero(&st.t_set, &new_partials) * r_new_inv;
    let hpw_new = ac::hash_g1_and_bytes_to_32(b"augsso/hpw/v1", &sigma_new, &st.new_password);
    let new_kp = ac::pke_kg(&hpw_new);

    if let Some(ns) = ctch_nonces {
        if ns.len() != st.nsp {
            return None;
        }
    }

    let mut ct_ch = Vec::with_capacity(st.nsp);
    for (idx, (sid, ch, ek, _)) in decoded.iter().enumerate() {
        let mut pt = [0u8; UPDATE_CTCH_PT_LEN];
        pt[0..augsso::CH_LEN].copy_from_slice(ch);
        pt[augsso::CH_LEN..].copy_from_slice(&new_kp.pk);
        let blob = if let Some(ns) = ctch_nonces {
            ac::xchacha_encrypt_detached_with_nonce::<UPDATE_CTCH_PT_LEN>(ek, &aad, &pt, &ns[idx])
        } else {
            ac::xchacha_encrypt_detached::<UPDATE_CTCH_PT_LEN>(ek, &aad, &pt, rng)
        };
        ct_ch.push((*sid, blob));
    }

    Some(PasswordUpdateClientPhase1 { ct_ch })
}

fn password_update_respond2(
    srv: &augsso::AugSsoServer,
    sess: &PasswordUpdateServerSession,
    ct_ch: &crypto_core::CtBlob<UPDATE_CTCH_PT_LEN>,
) -> Option<PasswordUpdateResponse2> {
    if srv.id != sess.server_id || srv.get_record(sess.client_id).is_none() {
        return None;
    }
    let aad: [u8; 0] = [];
    let pt = ac::xchacha_decrypt_detached::<UPDATE_CTCH_PT_LEN>(&sess.ek, &aad, ct_ch).ok()?;
    if pt[0..augsso::CH_LEN] != sess.ch[..] {
        return None;
    }

    let mut new_rpk = [0u8; ac::PKE_PK_LEN];
    new_rpk.copy_from_slice(&pt[augsso::CH_LEN..]);

    let bpw_new = ac::g1_from_bytes(&sess.bpw_new)?;
    let sigma_phi_i = ac::g1_to_bytes(&(bpw_new * srv.phi_i));
    Some(PasswordUpdateResponse2 {
        server_id: srv.id,
        sigma_phi_i,
        new_rpk,
    })
}

fn password_update_client_finalize(
    st: &PasswordUpdateClientState,
    req: &PasswordUpdateRequest,
    resps: &[PasswordUpdateResponse2],
    phi_pub_shares: &[(u32, ac::G2)],
) -> Option<[u8; 32]> {
    let bpw_new = ac::g1_from_bytes(&req.bpw_new)?;
    let mut partials = Vec::with_capacity(st.t_set.len());
    for sid in &st.t_set {
        let resp = resps.iter().find(|r| r.server_id == *sid)?;
        let sigma = ac::g1_from_bytes(&resp.sigma_phi_i)?;
        let phi_pub_i = phi_pub_shares
            .iter()
            .find(|(id, _)| *id == *sid)
            .map(|(_, pk)| *pk)?;
        if !ac::pairing_check_g1_g2(&sigma, &bpw_new, &phi_pub_i) {
            return None;
        }
        partials.push(sigma);
    }
    let r_new_inv = Option::<ac::Scalar>::from(st.r_new.invert())?;
    let sigma_phi = ac::combine_g1_at_zero(&st.t_set, &partials) * r_new_inv;
    Some(ac::hash_g1_and_bytes_to_32(
        b"augsso/popular-password-harden/v1",
        &sigma_phi,
        &st.new_password,
    ))
}

fn password_update_client_cpu_once(
    fx: &augsso::Fixture,
    new_password: &[u8],
    rng_in_timed: bool,
    it: &PasswordUpdateIterData,
    rng_req: &mut impl RngCore,
    rng_cli: &mut impl RngCore,
    rng_srv: &mut impl RngCore,
) -> Option<u128> {
    let t0 = Instant::now();
    let (st, req) = if rng_in_timed {
        password_update_request(fx, new_password, rng_req)
    } else {
        password_update_request_with_r(fx, new_password, it.r_old, it.r_new)
    };
    let t_req = t0.elapsed();

    let mut resps1 = Vec::with_capacity(fx.n);
    let mut sessions = Vec::with_capacity(fx.n);
    for j in 0..fx.n {
        let out = if rng_in_timed {
            password_update_respond1(&fx.servers[j], &req, rng_srv)
        } else {
            password_update_respond1_with_rand(&fx.servers[j], &req, &it.respond1_rand[j])
        }?;
        resps1.push(out.0);
        sessions.push(out.1);
    }

    let t1 = Instant::now();
    let phase1 = password_update_client_phase1(
        &st,
        &req,
        &resps1,
        &fx.pk_shares,
        if rng_in_timed { None } else { Some(&it.ctch_nonces) },
        rng_cli,
    )?;
    let t_phase1 = t1.elapsed();

    let mut resps2 = Vec::with_capacity(fx.n);
    let mut updated_servers = fx.servers.clone();
    for j in 0..fx.n {
        let sid = (j + 1) as u32;
        let ct_ch = phase1.ct_ch.iter().find(|(id, _)| *id == sid).map(|(_, ct)| ct)?;
        let resp = password_update_respond2(&updated_servers[j], &sessions[j], ct_ch)?;

        let sk_i = updated_servers[j].get_record(fx.c)?.sk_i;
        let msg = augsso::RegistrationMsg {
            server_id: sid,
            sk_i,
            rpk: resp.new_rpk,
        };
        updated_servers[j].store(fx.c, &msg);
        resps2.push(resp);
    }
    black_box(&updated_servers);

    let phi_pub_shares: Vec<(u32, ac::G2)> = fx.servers.iter().map(|srv| (srv.id, srv.phi_pub_i)).collect();
    let t2 = Instant::now();
    let hpwg = password_update_client_finalize(&st, &req, &resps2, &phi_pub_shares)?;
    black_box(hpwg);
    let t_fin = t2.elapsed();

    Some((t_req + t_phase1 + t_fin).as_nanos())
}

fn seed_for(tag: &[u8], nsp: usize, tsp: usize) -> [u8; 32] {
    use blake3;
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&(nsp as u64).to_le_bytes());
    h.update(&(tsp as u64).to_le_bytes());
    let out = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(out.as_bytes());
    seed
}

#[derive(Clone, Copy, Debug)]
struct ServerProcP50 {
    auth_respond1_ns: u64,
    auth_respond2_ns: u64,
    auth_total_ns: u64,
    update_respond1_ns: u64,
    update_respond2_ns: u64,
    update_total_ns: u64,
    store_ns: u64,
}

fn measure_server_procs_p50(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
) -> ServerProcP50 {
    let fx = augsso::make_fixture(nsp, tsp);
    let srv = &fx.servers[0];

    let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proc/auth_it", nsp, tsp));
    let it = augsso::make_iter_data(&fx, &mut rng_it);
    let (_st_client, creq) = augsso::request_with_r(&fx.password, fx.pld, &fx.t_set, it.r);

    let mut rng_resp1 = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proc/auth_respond1_rng", nsp, tsp));
    for _ in 0..warmup {
        let out = if rng_in_timed {
            augsso::respond1(srv, &creq, &mut rng_resp1)
        } else {
            augsso::respond1_with_rand(srv, &creq, &it.r1[0])
        };
        black_box(out);
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| {
            if rng_in_timed {
                augsso::respond1(srv, &creq, &mut rng_resp1)
            } else {
                augsso::respond1_with_rand(srv, &creq, &it.r1[0])
            }
        }));
    }
    let auth_respond1_ns = median_ns(xs);

    let (_resp1, sess) = augsso::respond1_with_rand(srv, &creq, &it.r1[0]).unwrap();
    let auth_ctch = {
        let aad: [u8; 0] = [];
        ac::xchacha_encrypt_detached_with_nonce::<{ augsso::CTCH_PT_LEN }>(
            &sess.ek,
            &aad,
            &sess.ch,
            &it.ctch_nonces[0],
        )
    };
    let mut rng_resp2 = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proc/auth_respond2_rng", nsp, tsp));
    for _ in 0..warmup {
        let out = if rng_in_timed {
            augsso::respond2(srv, &sess, &auth_ctch, &mut rng_resp2)
        } else {
            augsso::respond2_with_nonce(srv, &sess, &auth_ctch, &it.cttkn_nonces[0])
        };
        black_box(out);
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| {
            if rng_in_timed {
                augsso::respond2(srv, &sess, &auth_ctch, &mut rng_resp2)
            } else {
                augsso::respond2_with_nonce(srv, &sess, &auth_ctch, &it.cttkn_nonces[0])
            }
        }));
    }
    let auth_respond2_ns = median_ns(xs);
    let auth_total_ns = auth_respond1_ns.saturating_add(auth_respond2_ns);

    let new_password = b"new correct horse battery staple";
    let mut upd_rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proc/update_it", nsp, tsp));
    let upd_it = make_password_update_iter_data(&fx, &mut upd_rng_it);
    let (_upd_st, upd_req) = password_update_request_with_r(&fx, new_password, upd_it.r_old, upd_it.r_new);
    let mut upd_rng_srv =
        ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proc/update_respond1_rng", nsp, tsp));
    for _ in 0..warmup {
        let out = if rng_in_timed {
            password_update_respond1(srv, &upd_req, &mut upd_rng_srv)
        } else {
            password_update_respond1_with_rand(srv, &upd_req, &upd_it.respond1_rand[0])
        };
        black_box(out);
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| {
            if rng_in_timed {
                password_update_respond1(srv, &upd_req, &mut upd_rng_srv)
            } else {
                password_update_respond1_with_rand(srv, &upd_req, &upd_it.respond1_rand[0])
            }
        }));
    }
    let update_respond1_ns = median_ns(xs);

    let (_upd_resp1, upd_sess) =
        password_update_respond1_with_rand(srv, &upd_req, &upd_it.respond1_rand[0]).unwrap();
    let update_ctch = {
        let new_kp = ac::pke_kg(&[91u8; 32]);
        let mut pt = [0u8; UPDATE_CTCH_PT_LEN];
        pt[0..augsso::CH_LEN].copy_from_slice(&upd_sess.ch);
        pt[augsso::CH_LEN..].copy_from_slice(&new_kp.pk);
        let aad: [u8; 0] = [];
        ac::xchacha_encrypt_detached_with_nonce::<UPDATE_CTCH_PT_LEN>(
            &upd_sess.ek,
            &aad,
            &pt,
            &upd_it.ctch_nonces[0],
        )
    };
    for _ in 0..warmup {
        black_box(password_update_respond2(srv, &upd_sess, &update_ctch));
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| {
            password_update_respond2(srv, &upd_sess, &update_ctch)
        }));
    }
    let update_respond2_ns = median_ns(xs);
    let update_total_ns = update_respond1_ns.saturating_add(update_respond2_ns);

    let msg = {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proc/store_msg", nsp, tsp));
        augsso::registration_client(nsp, tsp, &fx.password, &mut rng).msgs[0].clone()
    };
    let mut srv2 = augsso::AugSsoServer::new(
        1,
        fx.servers[0].gamma_i,
        fx.servers[0].phi_i,
        fx.servers[0].gamma_pub_i,
        fx.servers[0].phi_pub_i,
        fx.servers[0].pp,
    );
    for _ in 0..warmup {
        srv2.store(fx.c, &msg);
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| srv2.store(fx.c, &msg)));
    }
    let store_ns = median_ns(xs);

    ServerProcP50 {
        auth_respond1_ns,
        auth_respond2_ns,
        auth_total_ns,
        update_respond1_ns,
        update_respond2_ns,
        update_total_ns,
        store_ns,
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
    let scheme = "augsso";
    let fx = augsso::make_fixture(nsp, tsp);

    {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proto/setup_rng", nsp, tsp));
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                black_box(augsso::setup(nsp, tsp, &mut rng));
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "proto", "setup", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proto/reg_rng", nsp, tsp));
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                black_box(augsso::registration_client(nsp, tsp, &fx.password, &mut rng));
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "proto", "reg", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    {
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proto/auth_it", nsp, tsp));
        let mut rng_req = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proto/auth_req_rng", nsp, tsp));
        let mut rng_cli = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proto/auth_cli_rng", nsp, tsp));
        let mut rng_srv = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proto/auth_srv_rng", nsp, tsp));

        let mut one_iter = || -> Option<u128> {
            let it = augsso::make_iter_data(&fx, &mut rng_it);
            let t0 = Instant::now();
            let (st_client, creq) = if rng_in_timed {
                augsso::request(&fx.password, fx.pld, &fx.t_set, &mut rng_req)
            } else {
                augsso::request_with_r(&fx.password, fx.pld, &fx.t_set, it.r)
            };
            let t_req = t0.elapsed();

            let mut resps1 = Vec::with_capacity(tsp);
            let mut sessions = Vec::with_capacity(tsp);
            for j in 0..tsp {
                let outv = if rng_in_timed {
                    augsso::respond1(&fx.servers[j], &creq, &mut rng_srv)
                } else {
                    augsso::respond1_with_rand(&fx.servers[j], &creq, &it.r1[j])
                }?;
                resps1.push(outv.0);
                sessions.push(outv.1);
            }

            let t1 = Instant::now();
            let phase1 = augsso::client_phase1(
                &st_client,
                &creq,
                &resps1,
                &fx.pk_shares,
                if rng_in_timed { None } else { Some(&it.ctch_nonces) },
                &mut rng_cli,
            )?;
            let t_phase1 = t1.elapsed();

            let mut resps2 = Vec::with_capacity(tsp);
            for j in 0..tsp {
                let sid = (j + 1) as u32;
                let ctch = phase1.ct_ch.iter().find(|(id, _)| *id == sid).map(|(_, ct)| ct)?;
                let outv = if rng_in_timed {
                    augsso::respond2(&fx.servers[j], &sessions[j], ctch, &mut rng_srv)
                } else {
                    augsso::respond2_with_nonce(&fx.servers[j], &sessions[j], ctch, &it.cttkn_nonces[j])
                }?;
                resps2.push(outv);
            }

            let t2 = Instant::now();
            let token = augsso::client_finalize(&st_client, &phase1, &resps2, &fx.gamma_pub_shares)?;
            black_box(token);
            let t_fin = t2.elapsed();
            Some((t_req + t_phase1 + t_fin).as_nanos())
        };

        let mut values = Vec::with_capacity(samples);
        for _ in 0..warmup {
            let _ = one_iter();
        }
        for _ in 0..samples {
            let mut attempts = 0usize;
            loop {
                if let Some(ns) = one_iter() {
                    values.push(ns);
                    break;
                }
                attempts += 1;
                if attempts >= 256 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("auth repeatedly failed (nsp={nsp}, tsp={tsp})"),
                    ));
                }
            }
        }
        let st = compute_stats(values);
        write_row(out, scheme, "proto", "auth", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    {
        let new_password = b"new correct horse battery staple";
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proto/update_it", nsp, tsp));
        let mut rng_req = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proto/update_req_rng", nsp, tsp));
        let mut rng_cli = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proto/update_cli_rng", nsp, tsp));
        let mut rng_srv = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/proto/update_srv_rng", nsp, tsp));

        let mut one_iter = || -> Option<u128> {
            let it = make_password_update_iter_data(&fx, &mut rng_it);
            password_update_client_cpu_once(
                &fx,
                new_password,
                rng_in_timed,
                &it,
                &mut rng_req,
                &mut rng_cli,
                &mut rng_srv,
            )
        };

        let mut values = Vec::with_capacity(samples);
        for _ in 0..warmup {
            let _ = one_iter();
        }
        for _ in 0..samples {
            let mut attempts = 0usize;
            loop {
                if let Some(ns) = one_iter() {
                    values.push(ns);
                    break;
                }
                attempts += 1;
                if attempts >= 256 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("password update repeatedly failed (nsp={nsp}, tsp={tsp})"),
                    ));
                }
            }
        }
        let st = compute_stats(values);
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
    let scheme = "augsso";
    let fx = augsso::make_fixture(nsp, tsp);
    let srv = &fx.servers[0];

    {
        let msg = {
            let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/sp/reg_msg", nsp, tsp));
            augsso::registration_client(nsp, tsp, &fx.password, &mut rng).msgs[0].clone()
        };
        let mut target = augsso::AugSsoServer::new(
            1,
            fx.servers[0].gamma_i,
            fx.servers[0].phi_i,
            fx.servers[0].gamma_pub_i,
            fx.servers[0].phi_pub_i,
            fx.servers[0].pp,
        );
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                target.store(fx.c, &msg);
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
        let st = bench_u128(|| time_call_ns(|| srv.has_record(fx.c)) as u128, warmup, samples);
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
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/sp/auth1_it", nsp, tsp));
        let it = augsso::make_iter_data(&fx, &mut rng_it);
        let (_, req) = augsso::request_with_r(&fx.password, fx.pld, &fx.t_set, it.r);
        let mut rng_srv = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/sp/auth1_rng", nsp, tsp));
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let result = if rng_in_timed {
                    augsso::respond1(srv, &req, &mut rng_srv)
                } else {
                    augsso::respond1_with_rand(srv, &req, &it.r1[0])
                };
                black_box(result);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "sp",
            "auth_respond1",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/sp/auth2_it", nsp, tsp));
        let it = augsso::make_iter_data(&fx, &mut rng_it);
        let (_, req) = augsso::request_with_r(&fx.password, fx.pld, &fx.t_set, it.r);
        let (_, sess) = augsso::respond1_with_rand(srv, &req, &it.r1[0]).unwrap();
        let aad: [u8; 0] = [];
        let ctch = ac::xchacha_encrypt_detached_with_nonce::<{ augsso::CTCH_PT_LEN }>(
            &sess.ek,
            &aad,
            &sess.ch,
            &it.ctch_nonces[0],
        );
        let mut rng_srv = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/sp/auth2_rng", nsp, tsp));
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let result = if rng_in_timed {
                    augsso::respond2(srv, &sess, &ctch, &mut rng_srv)
                } else {
                    augsso::respond2_with_nonce(srv, &sess, &ctch, &it.cttkn_nonces[0])
                };
                black_box(result);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "sp",
            "auth_respond2",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    let new_password = b"new correct horse battery staple";
    let mut upd_rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/sp/update_it", nsp, tsp));
    let upd_it = make_password_update_iter_data(&fx, &mut upd_rng_it);
    let (_, upd_req) = password_update_request_with_r(&fx, new_password, upd_it.r_old, upd_it.r_new);
    {
        let mut rng_srv = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/sp/update1_rng", nsp, tsp));
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let result = if rng_in_timed {
                    password_update_respond1(srv, &upd_req, &mut rng_srv)
                } else {
                    password_update_respond1_with_rand(srv, &upd_req, &upd_it.respond1_rand[0])
                };
                black_box(result);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "sp",
            "update_respond1",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let (_, sess) = password_update_respond1_with_rand(srv, &upd_req, &upd_it.respond1_rand[0]).unwrap();
        let new_kp = ac::pke_kg(&[91u8; 32]);
        let mut pt = [0u8; UPDATE_CTCH_PT_LEN];
        pt[0..augsso::CH_LEN].copy_from_slice(&sess.ch);
        pt[augsso::CH_LEN..].copy_from_slice(&new_kp.pk);
        let aad: [u8; 0] = [];
        let ctch = ac::xchacha_encrypt_detached_with_nonce::<UPDATE_CTCH_PT_LEN>(
            &sess.ek,
            &aad,
            &pt,
            &upd_it.ctch_nonces[0],
        );
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                black_box(password_update_respond2(srv, &sess, &ctch));
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "sp",
            "update_respond2",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    let proc = measure_server_procs_p50(nsp, tsp, warmup, samples, rng_in_timed);
    {
        let st = compute_stats(vec![proc.auth_total_ns as u128; samples.max(1)]);
        write_row(
            out,
            scheme,
            "sp",
            "auth_total_p50sum",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }
    {
        let st = compute_stats(vec![proc.update_total_ns as u128; samples.max(1)]);
        write_row(
            out,
            scheme,
            "sp",
            "update_total_p50sum",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    Ok(())
}

fn bench_primitives(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "augsso";
    let fx = augsso::make_fixture(nsp, tsp);

    {
        let pw = fx.password.clone();
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let p = ac::hash_to_g1(b"augsso/H_pw/v1", &pw);
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
            "hash_to_g1_pw",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let pld = fx.pld;
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let p = ac::hash_to_g1(b"augsso/H_pld/v1", &pld);
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
            "hash_to_g1_pld",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let ids: Vec<u32> = (1..=tsp as u32).collect();
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let ls = ac::lagrange_coeffs_at_zero(&ids);
                black_box(ls);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "lagrange_coeffs",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let ids: Vec<u32> = (1..=tsp as u32).collect();
        let points: Vec<ac::G1> = (0..tsp)
            .map(|i| ac::hash_to_g1(b"augsso/prim/pt", &[(i as u8)]))
            .collect();
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let p = ac::combine_g1_at_zero(&ids, &points);
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
            "combine_g1",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let pld = fx.pld;
        let h = ac::hash_to_g1(b"augsso/H_pld/v1", &pld);
        let pk = fx.gamma_pk;
        let sig = h * fx.servers[0].gamma_i;
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let ok = ac::pairing_check_sig(&h, &sig, &pk);
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
            "pairing_check",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let hpw = [42u8; 32];
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let kp = ac::pke_kg(&hpw);
                black_box(kp);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "prim", "pke_kg", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    {
        let hpw = [7u8; 32];
        let kp = ac::pke_kg(&hpw);
        let pt = [9u8; augsso::PKE_PT_LEN];
        let aad: [u8; 0] = [];
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/prim/pke_enc_rng", nsp, tsp));
        let eph = [1u8; 32];
        let nonce = [2u8; crypto_core::NONCE_LEN];

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let ct = if rng_in_timed {
                    ac::pke_enc::<{ augsso::PKE_PT_LEN }>(&kp.pk, &aad, &pt, &mut rng)
                } else {
                    ac::pke_enc_with_eph_and_nonce::<{ augsso::PKE_PT_LEN }>(&kp.pk, &aad, &pt, &eph, &nonce)
                };
                black_box(ct);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "pke_encrypt",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let hpw = [7u8; 32];
        let kp = ac::pke_kg(&hpw);
        let pt = [9u8; augsso::PKE_PT_LEN];
        let aad: [u8; 0] = [];
        let eph = [1u8; 32];
        let nonce = [2u8; crypto_core::NONCE_LEN];
        let ct = ac::pke_enc_with_eph_and_nonce::<{ augsso::PKE_PT_LEN }>(&kp.pk, &aad, &pt, &eph, &nonce);

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = ac::pke_dec::<{ augsso::PKE_PT_LEN }>(&kp.sk, &aad, &ct);
                let _ = black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "pke_decrypt",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let key = [3u8; 32];
        let aad: [u8; 0] = [];
        let pt = [4u8; augsso::CTCH_PT_LEN];
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/prim/aead32_rng", nsp, tsp));
        let nonce = [5u8; crypto_core::NONCE_LEN];

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let ct = if rng_in_timed {
                    crypto_core::xchacha_encrypt_detached::<{ augsso::CTCH_PT_LEN }>(
                        &key, &aad, &pt, &mut rng,
                    )
                } else {
                    crypto_core::xchacha_encrypt_detached_with_nonce::<{ augsso::CTCH_PT_LEN }>(
                        &key, &aad, &pt, &nonce,
                    )
                };
                black_box(ct);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "aead_encrypt_32",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let key = [3u8; 32];
        let aad: [u8; 0] = [];
        let pt = [4u8; augsso::CTCH_PT_LEN];
        let nonce = [5u8; crypto_core::NONCE_LEN];
        let ct = crypto_core::xchacha_encrypt_detached_with_nonce::<{ augsso::CTCH_PT_LEN }>(
            &key, &aad, &pt, &nonce,
        );

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = crypto_core::xchacha_decrypt_detached::<{ augsso::CTCH_PT_LEN }>(&key, &aad, &ct);
                let _ = black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "aead_decrypt_32",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let key = [6u8; 32];
        let aad: [u8; 0] = [];
        let pt = [7u8; 112];
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/prim/aead112_rng", nsp, tsp));
        let nonce = [8u8; crypto_core::NONCE_LEN];

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let ct = if rng_in_timed {
                    crypto_core::xchacha_encrypt_detached::<112>(&key, &aad, &pt, &mut rng)
                } else {
                    crypto_core::xchacha_encrypt_detached_with_nonce::<112>(&key, &aad, &pt, &nonce)
                };
                black_box(ct);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "aead_encrypt_112",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let key = [6u8; 32];
        let aad: [u8; 0] = [];
        let pt = [7u8; 112];
        let nonce = [8u8; crypto_core::NONCE_LEN];
        let ct = crypto_core::xchacha_encrypt_detached_with_nonce::<112>(&key, &aad, &pt, &nonce);

        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = crypto_core::xchacha_decrypt_detached::<112>(&key, &aad, &ct);
                let _ = black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "aead_decrypt_112",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    Ok(())
}

fn bench_net(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    prof: NetProfile,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "augsso";

    {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/net/reg", nsp, tsp));
        let st = bench_u128(
            || {
                simulate_parallel_phase(
                    nsp,
                    REG_REQ_BYTES_PER_SERVER,
                    REG_RESP_BYTES_PER_SERVER,
                    0,
                    prof,
                    &mut rng,
                ) as u128
            },
            warmup,
            samples,
        );
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
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/net/auth", nsp, tsp));
        let st = bench_u128(
            || {
                let r1 = simulate_parallel_phase(
                    tsp,
                    AUTH_REQ1_BYTES_PER_SERVER,
                    AUTH_RESP1_BYTES_PER_SERVER,
                    0,
                    prof,
                    &mut rng,
                );
                let r2 = simulate_parallel_phase(
                    tsp,
                    AUTH_REQ2_BYTES_PER_SERVER,
                    AUTH_RESP2_BYTES_PER_SERVER,
                    0,
                    prof,
                    &mut rng,
                );
                (r1 as u128) + (r2 as u128)
            },
            warmup,
            samples,
        );
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
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/net/update", nsp, tsp));
        let st = bench_u128(
            || {
                let r1 = simulate_parallel_phase(
                    nsp,
                    UPDATE_REQ1_BYTES_PER_SERVER,
                    UPDATE_RESP1_BYTES_PER_SERVER,
                    0,
                    prof,
                    &mut rng,
                );
                let r2 = simulate_parallel_phase(
                    nsp,
                    UPDATE_REQ2_BYTES_PER_SERVER,
                    UPDATE_RESP2_BYTES_PER_SERVER,
                    0,
                    prof,
                    &mut rng,
                );
                (r1 as u128) + (r2 as u128)
            },
            warmup,
            samples,
        );
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
    let scheme = "augsso";
    let proc = measure_server_procs_p50(nsp, tsp, proc_warmup, proc_samples, rng_in_timed);

    {
        let mut rng_reg = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/full/reg_rng", nsp, tsp));
        let mut rng_net = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/full/reg_net", nsp, tsp));
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                black_box(augsso::registration_client(
                    nsp,
                    tsp,
                    b"correct horse battery staple",
                    &mut rng_reg,
                ));
                let client_ns = t0.elapsed().as_nanos() as u64;
                let network_ns = simulate_parallel_phase(
                    nsp,
                    REG_REQ_BYTES_PER_SERVER,
                    REG_RESP_BYTES_PER_SERVER,
                    proc.store_ns,
                    prof,
                    &mut rng_net,
                );
                (client_ns as u128) + (network_ns as u128)
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
        let fx = augsso::make_fixture(nsp, tsp);
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/full/auth_it", nsp, tsp));
        let mut rng_net = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/full/auth_net", nsp, tsp));
        let mut rng_req = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/full/auth_req", nsp, tsp));
        let mut rng_cli = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/full/auth_cli", nsp, tsp));
        let mut rng_srv = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/full/auth_srv", nsp, tsp));

        let st = bench_u128(
            || {
                let it = augsso::make_iter_data(&fx, &mut rng_it);
                let t0 = Instant::now();
                let (client_st, req) = if rng_in_timed {
                    augsso::request(&fx.password, fx.pld, &fx.t_set, &mut rng_req)
                } else {
                    augsso::request_with_r(&fx.password, fx.pld, &fx.t_set, it.r)
                };
                let t_req = t0.elapsed();

                let mut resps1 = Vec::with_capacity(tsp);
                let mut sessions = Vec::with_capacity(tsp);
                for j in 0..tsp {
                    let outv = if rng_in_timed {
                        augsso::respond1(&fx.servers[j], &req, &mut rng_srv)
                    } else {
                        augsso::respond1_with_rand(&fx.servers[j], &req, &it.r1[j])
                    }
                    .expect("fixture auth respond1");
                    resps1.push(outv.0);
                    sessions.push(outv.1);
                }

                let t1 = Instant::now();
                let phase1 = augsso::client_phase1(
                    &client_st,
                    &req,
                    &resps1,
                    &fx.pk_shares,
                    if rng_in_timed { None } else { Some(&it.ctch_nonces) },
                    &mut rng_cli,
                )
                .expect("fixture auth client phase1");
                let t_phase1 = t1.elapsed();

                let mut resps2 = Vec::with_capacity(tsp);
                for j in 0..tsp {
                    let sid = (j + 1) as u32;
                    let ctch = phase1
                        .ct_ch
                        .iter()
                        .find(|(id, _)| *id == sid)
                        .map(|(_, ct)| ct)
                        .expect("ctch");
                    let outv = if rng_in_timed {
                        augsso::respond2(&fx.servers[j], &sessions[j], ctch, &mut rng_srv)
                    } else {
                        augsso::respond2_with_nonce(&fx.servers[j], &sessions[j], ctch, &it.cttkn_nonces[j])
                    }
                    .expect("fixture auth respond2");
                    resps2.push(outv);
                }

                let t2 = Instant::now();
                let token = augsso::client_finalize(&client_st, &phase1, &resps2, &fx.gamma_pub_shares)
                    .expect("fixture auth finalize");
                let t_fin = t2.elapsed();

                let t3 = Instant::now();
                let valid = augsso::verify_token(&fx.gamma_pk, &token);
                black_box(valid);
                let t_verify = t3.elapsed();

                let client_and_verify_ns = (t_req + t_phase1 + t_fin + t_verify).as_nanos() as u64;
                let net1 = simulate_parallel_phase(
                    tsp,
                    AUTH_REQ1_BYTES_PER_SERVER,
                    AUTH_RESP1_BYTES_PER_SERVER,
                    proc.auth_respond1_ns,
                    prof,
                    &mut rng_net,
                );
                let net2 = simulate_parallel_phase(
                    tsp,
                    AUTH_REQ2_BYTES_PER_SERVER,
                    AUTH_RESP2_BYTES_PER_SERVER,
                    proc.auth_respond2_ns,
                    prof,
                    &mut rng_net,
                );
                (client_and_verify_ns as u128) + (net1 as u128) + (net2 as u128)
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
        let fx = augsso::make_fixture(nsp, tsp);
        let new_password = b"new correct horse battery staple";
        let mut rng_it = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/full/update_it", nsp, tsp));
        let mut rng_net = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/full/update_net", nsp, tsp));
        let mut rng_req = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/full/update_req", nsp, tsp));
        let mut rng_cli = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/full/update_cli", nsp, tsp));
        let mut rng_srv = ChaCha20Rng::from_seed(seed_for(b"bench_augsso/full/update_srv", nsp, tsp));

        let st = bench_u128(
            || {
                let it = make_password_update_iter_data(&fx, &mut rng_it);
                let client_ns = password_update_client_cpu_once(
                    &fx,
                    new_password,
                    rng_in_timed,
                    &it,
                    &mut rng_req,
                    &mut rng_cli,
                    &mut rng_srv,
                )
                .expect("fixture password update") as u64;

                let net1 = simulate_parallel_phase(
                    nsp,
                    UPDATE_REQ1_BYTES_PER_SERVER,
                    UPDATE_RESP1_BYTES_PER_SERVER,
                    proc.update_respond1_ns,
                    prof,
                    &mut rng_net,
                );
                let net2 = simulate_parallel_phase(
                    nsp,
                    UPDATE_REQ2_BYTES_PER_SERVER,
                    UPDATE_RESP2_BYTES_PER_SERVER,
                    proc.update_respond2_ns,
                    prof,
                    &mut rng_net,
                );
                (client_ns as u128) + (net1 as u128) + (net2 as u128)
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

fn parse_usize_list(s: &str) -> Vec<usize> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| x.trim().parse::<usize>().expect("bad integer"))
        .collect()
}

fn ceil_pct(n: usize, pct: usize) -> usize {
    let num = n * pct;
    (num + 99) / 100
}

pub fn run(args: Vec<String>) -> std::io::Result<()> {
    let mut nsp_list = vec![20usize, 40, 60];
    let mut tsp_list: Option<Vec<usize>> = None;
    let mut tsp_pct_list: Option<Vec<usize>> = Some(vec![50]);

    let mut kind = "all".to_string();
    let mut net = "all".to_string();
    let mut out_path = "augsso_bench.txt".to_string();

    let mut warmup = 50usize;
    let mut samples = 200usize;

    let mut rng_in_timed = false;

    let mut proc_warmup = 50usize;
    let mut proc_samples = 200usize;

    let mut lan_rtt_ms: f64 = 1.0;
    let mut lan_jitter_ms: f64 = 0.5;
    let mut lan_bw_mbps: f64 = 1000.0;

    let mut wan_rtt_ms: f64 = 50.0;
    let mut wan_jitter_ms: f64 = 5.0;
    let mut wan_bw_mbps: f64 = 50.0;

    let mut overhead_bytes: usize = 40;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--kind" => {
                i += 1;
                kind = args[i].clone();
            }
            "--net" => {
                i += 1;
                net = args[i].clone();
            }
            "--nsp" => {
                i += 1;
                nsp_list = parse_usize_list(&args[i]);
            }
            "--tsp" => {
                i += 1;
                tsp_list = Some(parse_usize_list(&args[i]));
                tsp_pct_list = None;
            }
            "--tsp-pct" => {
                i += 1;
                tsp_pct_list = Some(parse_usize_list(&args[i]));
                tsp_list = None;
            }
            "--warmup" => {
                i += 1;
                warmup = args[i].parse().expect("bad warmup");
            }
            "--warmup-iters" => {
                i += 1;
                warmup = args[i].parse().expect("bad warmup-iters");
            }
            "--samples" => {
                i += 1;
                samples = args[i].parse().expect("bad samples");
            }
            "--sample-size" => {
                i += 1;
                samples = args[i].parse().expect("bad sample-size");
            }
            "--out" => {
                i += 1;
                out_path = args[i].clone();
            }
            "--rng-in-timed" => {
                rng_in_timed = true;
            }
            "--proc-warmup" => {
                i += 1;
                proc_warmup = args[i].parse().expect("bad proc_warmup");
            }
            "--proc-samples" => {
                i += 1;
                proc_samples = args[i].parse().expect("bad proc_samples");
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
            "--help" | "-h" => {
                eprintln!(
                    "Usage: bench_augsso [--kind proto|sp|prim|net|full|all] [--net lan|wan|all]\n\
                     \t[--nsp 20,40,60] [--tsp 10,20] | [--tsp-pct 50]\n\
                     \t[--warmup-iters N | --warmup N] [--sample-size N | --samples N]\n\
                     \t[--proc-warmup N] [--proc-samples N]\n\
                     \t[--lan-rtt-ms f] [--lan-jitter-ms f] [--lan-bw-mbps f]\n\
                     \t[--wan-rtt-ms f] [--wan-jitter-ms f] [--wan-bw-mbps f]\n\
                     \t[--overhead-bytes N]\n\
                     \t[--rng-in-timed] [--out path]"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown arg: {}", other);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let f = File::create(&out_path)?;
    let mut out = BufWriter::new(f);
    write_header(&mut out)?;

    let lan = mk_profile("lan", lan_rtt_ms, lan_jitter_ms, lan_bw_mbps, overhead_bytes);
    let wan = mk_profile("wan", wan_rtt_ms, wan_jitter_ms, wan_bw_mbps, overhead_bytes);

    for &nsp in &nsp_list {
        if let Some(tsps) = tsp_list.as_ref() {
            for &tsp in tsps {
                run_one(
                    nsp,
                    tsp,
                    &kind,
                    &net,
                    warmup,
                    samples,
                    rng_in_timed,
                    proc_warmup,
                    proc_samples,
                    lan,
                    wan,
                    &mut out,
                )?;
            }
        } else {
            let pcts: Vec<usize> = tsp_pct_list.clone().unwrap_or_else(|| vec![50]);
            for &pct in &pcts {
                let tsp = ceil_pct(nsp, pct);
                run_one(
                    nsp,
                    tsp,
                    &kind,
                    &net,
                    warmup,
                    samples,
                    rng_in_timed,
                    proc_warmup,
                    proc_samples,
                    lan,
                    wan,
                    &mut out,
                )?;
            }
        }
    }

    out.flush()?;
    Ok(())
}

fn run_one(
    nsp: usize,
    tsp: usize,
    kind: &str,
    net: &str,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    proc_warmup: usize,
    proc_samples: usize,
    lan: NetProfile,
    wan: NetProfile,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let kinds: Vec<&str> = kind.split(',').map(str::trim).collect();
    let all = kinds.contains(&"all");
    let do_proto = all || kinds.contains(&"proto");
    let do_sp = all || kinds.contains(&"sp");
    let do_prim = all || kinds.contains(&"prim");
    let do_net = all || kinds.contains(&"net");
    let do_full = all || kinds.contains(&"full");

    if do_proto {
        bench_client_proto(nsp, tsp, warmup, samples, rng_in_timed, out)?;
    }
    if do_sp {
        bench_server_phases(nsp, tsp, warmup, samples, rng_in_timed, out)?;
    }
    if do_prim {
        bench_primitives(nsp, tsp, warmup, samples, rng_in_timed, out)?;
    }
    if do_net {
        match net {
            "lan" => bench_net(nsp, tsp, warmup, samples, lan, out)?,
            "wan" => bench_net(nsp, tsp, warmup, samples, wan, out)?,
            "all" => {
                bench_net(nsp, tsp, warmup, samples, lan, out)?;
                bench_net(nsp, tsp, warmup, samples, wan, out)?;
            }
            _ => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad --net"));
            }
        }
    }
    if do_full {
        match net {
            "lan" => bench_full(
                nsp,
                tsp,
                warmup,
                samples,
                rng_in_timed,
                lan,
                proc_warmup,
                proc_samples,
                out,
            )?,
            "wan" => bench_full(
                nsp,
                tsp,
                warmup,
                samples,
                rng_in_timed,
                wan,
                proc_warmup,
                proc_samples,
                out,
            )?,
            "all" => {
                bench_full(
                    nsp,
                    tsp,
                    warmup,
                    samples,
                    rng_in_timed,
                    lan,
                    proc_warmup,
                    proc_samples,
                    out,
                )?;
                bench_full(
                    nsp,
                    tsp,
                    warmup,
                    samples,
                    rng_in_timed,
                    wan,
                    proc_warmup,
                    proc_samples,
                    out,
                )?;
            }
            _ => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad --net"));
            }
        }
    }

    Ok(())
}
