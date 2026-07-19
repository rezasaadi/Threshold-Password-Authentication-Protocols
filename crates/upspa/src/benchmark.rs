#![allow(clippy::needless_range_loop)]

use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::time::Instant;

use blake3;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use ed25519_dalek::{Signer, SigningKey};

use tspa::crypto as up_crypto;
use tspa::protocols::{sp as sp_mod, upspa as upspa_proto};

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, XNonce,
};

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

#[derive(Clone, Copy, Debug)]
struct ServerProcP50 {
    up_toprf_eval_ns: u64,
    up_db_get_ns: u64,
    up_db_put_ns: u64,
    up_pwdupd_apply_ns_v1: u64,
    up_pwdupd_apply_ns_v2: u64,
    up_setup_store_ns: u64,
}

fn measure_server_procs_p50(nsp: usize, tsp: usize, warmup: usize, samples: usize) -> ServerProcP50 {
    use curve25519_dalek::scalar::Scalar;
    use ed25519_dalek::{Signature, Verifier};

    let fx_up = upspa_proto::make_fixture(nsp, tsp);

    let mut up_prov =
        sp_mod::UpSpaProvider::new(1, fx_up.shares[0].1, fx_up.sig_pk_bytes, fx_up.cipherid.clone());

    let r = Scalar::from(5u64);
    let blinded = (fx_up.pwd_point * r).compress().to_bytes();

    for _ in 0..warmup {
        black_box(up_prov.toprf_send_eval(&blinded));
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| {
            let out = up_prov.toprf_send_eval(&blinded);
            black_box(out);
        }));
    }
    let up_toprf_eval_ns = median_ns(xs);

    let mut key0 = [0u8; 32];
    key0[0] = 1;
    let blob0 = fx_up.ciphersp_per_sp[0].clone();

    for i in 0..nsp {
        let mut k = [0u8; 32];
        k[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        up_prov.put_ciphersp(k, blob0.clone());
    }

    for _ in 0..warmup {
        black_box(up_prov.get_ciphersp(&key0));
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| {
            let out = up_prov.get_ciphersp(&key0);
            black_box(out);
        }));
    }
    let up_db_get_ns = median_ns(xs);

    for _ in 0..warmup {
        up_prov.put_ciphersp(key0, blob0.clone());
        black_box(&up_prov);
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| {
            up_prov.put_ciphersp(key0, blob0.clone());
            black_box(&up_prov);
        }));
    }
    let up_db_put_ns = median_ns(xs);

    let mut rng2 = ChaCha20Rng::from_seed(seed_for(b"bench_unified/proc/up/pwdupd_v1", nsp, tsp));
    let sid = SigningKey::generate(&mut rng2);
    let sig_pk_bytes = sid.verifying_key().to_bytes();
    let mut up_prov2 = sp_mod::UpSpaProvider::new(1, fx_up.shares[0].1, sig_pk_bytes, fx_up.cipherid.clone());

    const MSG_LEN_V1: usize = 24 + upspa_proto::CIPHERID_PT_LEN + 16 + 32 + 8 + 4;
    let mut msg_v1 = [0u8; MSG_LEN_V1];
    let mut off = 0;
    msg_v1[off..off + 24].copy_from_slice(&fx_up.cipherid.nonce);
    off += 24;
    msg_v1[off..off + upspa_proto::CIPHERID_PT_LEN].copy_from_slice(&fx_up.cipherid.ct);
    off += upspa_proto::CIPHERID_PT_LEN;
    msg_v1[off..off + 16].copy_from_slice(&fx_up.cipherid.tag);
    off += 16;
    msg_v1[off..off + 32].copy_from_slice(&fx_up.shares[0].1.to_bytes());
    off += 32;
    msg_v1[off..off + 8].copy_from_slice(&0u64.to_le_bytes());
    off += 8;
    msg_v1[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
    off += 4;
    debug_assert_eq!(off, MSG_LEN_V1);

    let sig_v1 = sid.sign(&msg_v1);

    for _ in 0..warmup {
        black_box(up_prov2.apply_password_update(&msg_v1, &sig_v1));
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| {
            let ok = up_prov2.apply_password_update(&msg_v1, &sig_v1);
            black_box(ok);
        }));
    }
    let up_pwdupd_apply_ns_v1 = median_ns(xs);

    const MSG_LEN_V2: usize = 24 + upspa_proto::CIPHERID_PT_LEN + 16 + 8;
    let mut msg_v2 = [0u8; MSG_LEN_V2];
    let mut off = 0;
    msg_v2[off..off + 24].copy_from_slice(&fx_up.cipherid.nonce);
    off += 24;
    msg_v2[off..off + upspa_proto::CIPHERID_PT_LEN].copy_from_slice(&fx_up.cipherid.ct);
    off += upspa_proto::CIPHERID_PT_LEN;
    msg_v2[off..off + 16].copy_from_slice(&fx_up.cipherid.tag);
    off += 16;
    msg_v2[off..off + 8].copy_from_slice(&0u64.to_le_bytes());
    off += 8;
    debug_assert_eq!(off, MSG_LEN_V2);

    let sig_v2: Signature = sid.sign(&msg_v2);

    for _ in 0..warmup {
        black_box(up_prov2.sig_pk.verify(&msg_v2, &sig_v2).is_ok());
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| {
            let ok = up_prov2.sig_pk.verify(&msg_v2, &sig_v2).is_ok();
            black_box(ok);
        }));
    }
    let up_pwdupd_apply_ns_v2 = median_ns(xs);

    for _ in 0..warmup {
        let p = sp_mod::UpSpaProvider::new(1, fx_up.shares[0].1, fx_up.sig_pk_bytes, fx_up.cipherid.clone());
        black_box(p);
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        xs.push(time_call_ns(|| {
            let p =
                sp_mod::UpSpaProvider::new(1, fx_up.shares[0].1, fx_up.sig_pk_bytes, fx_up.cipherid.clone());
            black_box(p);
        }));
    }
    let up_setup_store_ns = median_ns(xs);

    ServerProcP50 {
        up_toprf_eval_ns,
        up_db_get_ns,
        up_db_put_ns,
        up_pwdupd_apply_ns_v1,
        up_pwdupd_apply_ns_v2,
        up_setup_store_ns,
    }
}

fn upspa_aead_encrypt_fixed<const PT_LEN: usize>(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8; PT_LEN],
    nonce: [u8; up_crypto::NONCE_LEN],
) -> up_crypto::CtBlob<PT_LEN> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
    let xnonce = XNonce::from_slice(&nonce);

    let mut ct = *plaintext;
    let tag = cipher.encrypt_in_place_detached(xnonce, aad, &mut ct).unwrap();

    let mut tag_bytes = [0u8; up_crypto::TAG_LEN];
    tag_bytes.copy_from_slice(tag.as_slice());

    up_crypto::CtBlob {
        nonce,
        ct,
        tag: tag_bytes,
    }
}

fn upspa_recover_state_and_cipherid_pt(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
) -> ([u8; 32], [u8; upspa_proto::CIPHERID_PT_LEN]) {
    let b = &fx.pwd_point * it.r;
    black_box(b);

    let state_key =
        up_crypto::toprf_client_eval_from_partials(&fx.password, it.r, &it.partials, &fx.lagrange_at_zero);

    let pt = up_crypto::xchacha_decrypt_detached(&state_key, &fx.cipherid_aad, &fx.cipherid)
        .expect("cipherid must decrypt");

    (state_key, pt)
}

fn upspa_extract_rsp_fk_sid(
    cipherid_pt: &[u8; upspa_proto::CIPHERID_PT_LEN],
) -> ([u8; 32], [u8; 32], SigningKey) {
    let mut sid_bytes = [0u8; 32];
    sid_bytes.copy_from_slice(&cipherid_pt[0..32]);

    let mut rsp = [0u8; 32];
    rsp.copy_from_slice(&cipherid_pt[32..64]);

    let mut fk = [0u8; 32];
    fk.copy_from_slice(&cipherid_pt[64..96]);

    let sid = SigningKey::from_bytes(&sid_bytes);
    (rsp, fk, sid)
}

fn upspa_precompute_reg_rng_outputs(r: Scalar) -> ([u8; 32], [u8; up_crypto::NONCE_LEN]) {
    let mut seed = r.to_bytes();
    seed[0] ^= 0xA5;
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut rlsj = [0u8; 32];
    rng.fill_bytes(&mut rlsj);

    let mut nonce = [0u8; up_crypto::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    (rlsj, nonce)
}

fn upspa_precompute_secu_rng_outputs(r: Scalar) -> ([u8; 32], [u8; up_crypto::NONCE_LEN]) {
    let mut seed = r.to_bytes();
    seed[0] ^= 0x3C;
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut new_rlsj = [0u8; 32];
    rng.fill_bytes(&mut new_rlsj);

    let mut nonce = [0u8; up_crypto::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    (new_rlsj, nonce)
}

fn upspa_precompute_pwdupd_coeffs_and_nonce(
    r: Scalar,
    tsp: usize,
) -> (Vec<Scalar>, [u8; up_crypto::NONCE_LEN]) {
    let mut seed = r.to_bytes();
    seed[0] ^= 0x77;
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut coeffs = Vec::with_capacity(tsp);
    for _ in 0..tsp {
        coeffs.push(up_crypto::random_scalar(&mut rng));
    }

    let mut nonce = [0u8; up_crypto::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    (coeffs, nonce)
}

fn upspa_precompute_pwdupd_v2_nonce(r: Scalar) -> [u8; up_crypto::NONCE_LEN] {
    let mut seed = r.to_bytes();
    seed[0] ^= 0x78;
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut nonce = [0u8; up_crypto::NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    nonce
}

fn eval_poly_pow(coeffs: &[Scalar], x: Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    let mut pow = Scalar::ONE;
    for c in coeffs {
        acc += c * pow;
        pow *= x;
    }
    acc
}

fn upspa_registration_no_rng(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
    rlsj: [u8; 32],
    enc_nonce: [u8; up_crypto::NONCE_LEN],
) -> [u8; 32] {
    let (_state_key, cipherid_pt) = upspa_recover_state_and_cipherid_pt(fx, it);
    let (rsp, fk, _sid) = upspa_extract_rsp_fk_sid(&cipherid_pt);

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/registration/acc/v1");

    for i in 1..=fx.nsp {
        let suid = up_crypto::hash_suid(&rsp, &fx.lsj, i as u32);
        acc.update(suid.as_ref());
    }

    let ctr: u64 = 0;
    let mut pt = [0u8; upspa_proto::CIPHERSP_PT_LEN];
    pt[0..32].copy_from_slice(&rlsj);
    pt[32..40].copy_from_slice(&ctr.to_le_bytes());
    let cj = upspa_aead_encrypt_fixed(&fk, &fx.ciphersp_aad, &pt, enc_nonce);

    let vinfo = up_crypto::hash_vinfo(&rlsj, &fx.lsj);
    acc.update(vinfo.as_ref());
    acc.update(&cj.nonce);
    acc.update(&cj.ct);
    acc.update(&cj.tag);

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

fn upspa_secu_no_rng(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
    new_rlsj: [u8; 32],
    enc_nonce: [u8; up_crypto::NONCE_LEN],
) -> [u8; 32] {
    let (_state_key, cipherid_pt) = upspa_recover_state_and_cipherid_pt(fx, it);
    let (rsp, fk, _sid) = upspa_extract_rsp_fk_sid(&cipherid_pt);

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/secret_update/acc/v3");

    for i in 1..=fx.nsp {
        let suid = up_crypto::hash_suid(&rsp, &fx.lsj, i as u32);
        acc.update(suid.as_ref());
    }

    let mut old_ctr: u64 = 0;
    let mut old_rlsj = [0u8; 32];
    for &id in fx.ids_for_t.iter() {
        let blob = &fx.ciphersp_per_sp[(id - 1) as usize];
        let pt = up_crypto::xchacha_decrypt_detached(&fk, &fx.ciphersp_aad, blob).unwrap();

        let mut rlsj = [0u8; 32];
        rlsj.copy_from_slice(&pt[0..32]);

        let mut ctr_bytes = [0u8; 8];
        ctr_bytes.copy_from_slice(&pt[32..40]);
        let ctr = u64::from_le_bytes(ctr_bytes);

        if ctr >= old_ctr {
            old_ctr = ctr;
            old_rlsj = rlsj;
        }
    }

    let vinfo_prime = up_crypto::hash_vinfo(&old_rlsj, &fx.lsj);
    let new_ctr = old_ctr.wrapping_add(1);

    let mut pt = [0u8; upspa_proto::CIPHERSP_PT_LEN];
    pt[0..32].copy_from_slice(&new_rlsj);
    pt[32..40].copy_from_slice(&new_ctr.to_le_bytes());
    let newciphersp = upspa_aead_encrypt_fixed(&fk, &fx.ciphersp_aad, &pt, enc_nonce);

    let newvinfo = up_crypto::hash_vinfo(&new_rlsj, &fx.lsj);

    acc.update(&old_ctr.to_le_bytes());
    acc.update(vinfo_prime.as_ref());
    acc.update(&new_ctr.to_le_bytes());
    acc.update(newvinfo.as_ref());
    acc.update(&newciphersp.nonce);
    acc.update(&newciphersp.ct);
    acc.update(&newciphersp.tag);

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

fn upspa_pwdupd_no_rng(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
    coeffs: &[Scalar],
    newcipherid_nonce: [u8; up_crypto::NONCE_LEN],
) -> [u8; 32] {
    let (_state_key, cipherid_pt) = upspa_recover_state_and_cipherid_pt(fx, it);
    let (_rsp, _fk, sid) = upspa_extract_rsp_fk_sid(&cipherid_pt);

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/password_update/acc/v1");

    let new_master_sk = coeffs[0];

    let mut new_shares: Vec<(u32, Scalar)> = Vec::with_capacity(fx.nsp);
    for i in 1..=fx.nsp {
        let x = Scalar::from(i as u64);
        let s = eval_poly_pow(coeffs, x);
        new_shares.push((i as u32, s));
    }

    let p_new = up_crypto::hash_to_point(&fx.new_password);
    let y_new = p_new * new_master_sk;
    let new_state_key = up_crypto::oprf_finalize(&fx.new_password, &y_new);
    let newcipherid =
        upspa_aead_encrypt_fixed(&new_state_key, &fx.cipherid_aad, &cipherid_pt, newcipherid_nonce);

    let timestamp: u64 = 0;
    const MSG_LEN: usize = 24 + upspa_proto::CIPHERID_PT_LEN + 16 + 32 + 8 + 4;

    for (id, share) in new_shares.iter() {
        let i_u32 = *id;
        let share_bytes = share.to_bytes();

        let mut msg = [0u8; MSG_LEN];
        let mut off = 0;
        msg[off..off + 24].copy_from_slice(&newcipherid.nonce);
        off += 24;
        msg[off..off + upspa_proto::CIPHERID_PT_LEN].copy_from_slice(&newcipherid.ct);
        off += upspa_proto::CIPHERID_PT_LEN;
        msg[off..off + 16].copy_from_slice(&newcipherid.tag);
        off += 16;
        msg[off..off + 32].copy_from_slice(&share_bytes);
        off += 32;
        msg[off..off + 8].copy_from_slice(&timestamp.to_le_bytes());
        off += 8;
        msg[off..off + 4].copy_from_slice(&i_u32.to_le_bytes());
        off += 4;

        debug_assert_eq!(off, MSG_LEN);

        let sig = sid.sign(&msg);
        let sig_bytes = sig.to_bytes();

        acc.update(&i_u32.to_le_bytes());
        acc.update(&sig_bytes);
    }

    acc.update(&newcipherid.nonce);
    acc.update(&newcipherid.ct);
    acc.update(&newcipherid.tag);

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

fn upspa_pwdupd_v2_no_rng(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
    newcipherid_nonce: [u8; up_crypto::NONCE_LEN],
) -> [u8; 32] {
    let (_state_key, cipherid_pt) = upspa_recover_state_and_cipherid_pt(fx, it);
    let (_rsp, _fk, sid) = upspa_extract_rsp_fk_sid(&cipherid_pt);

    let p_new = up_crypto::hash_to_point(&fx.new_password);
    let blinded_new = p_new * it.r;
    black_box(blinded_new);

    let mut partials_new: Vec<RistrettoPoint> = Vec::with_capacity(fx.tsp);
    for &id in fx.ids_for_t.iter() {
        let share = fx.shares[(id - 1) as usize].1;
        partials_new.push(blinded_new * share);
    }

    let new_state_key = up_crypto::toprf_client_eval_from_partials(
        &fx.new_password,
        it.r,
        &partials_new,
        &fx.lagrange_at_zero,
    );

    let newcipherid =
        upspa_aead_encrypt_fixed(&new_state_key, &fx.cipherid_aad, &cipherid_pt, newcipherid_nonce);

    let timestamp: u64 = 0;
    const MSG_LEN: usize = 24 + upspa_proto::CIPHERID_PT_LEN + 16 + 8;
    let mut msg = [0u8; MSG_LEN];
    let mut off = 0;
    msg[off..off + 24].copy_from_slice(&newcipherid.nonce);
    off += 24;
    msg[off..off + upspa_proto::CIPHERID_PT_LEN].copy_from_slice(&newcipherid.ct);
    off += upspa_proto::CIPHERID_PT_LEN;
    msg[off..off + 16].copy_from_slice(&newcipherid.tag);
    off += 16;
    msg[off..off + 8].copy_from_slice(&timestamp.to_le_bytes());
    off += 8;
    debug_assert_eq!(off, MSG_LEN);

    let sig = sid.sign(&msg);
    let sig_bytes = sig.to_bytes();

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/password_update/acc/v2");
    acc.update(&sig_bytes);
    acc.update(&newcipherid.nonce);
    acc.update(&newcipherid.ct);
    acc.update(&newcipherid.tag);
    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

fn upspa_auth_two_decryptions(fx: &upspa_proto::Fixture, it: &upspa_proto::IterData) -> [u8; 32] {
    let (_state_key, cipherid_pt) = upspa_recover_state_and_cipherid_pt(fx, it);
    let (rsp, fk, _sid) = upspa_extract_rsp_fk_sid(&cipherid_pt);

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/authentication/acc/2dec_v1");

    for &id in fx.ids_for_t.iter() {
        let suid = up_crypto::hash_suid(&rsp, &fx.lsj, id);
        acc.update(suid.as_ref());
    }

    let id0 = fx.ids_for_t[0];
    let blob = &fx.ciphersp_per_sp[(id0 - 1) as usize];
    let pt = up_crypto::xchacha_decrypt_detached(&fk, &fx.ciphersp_aad, blob).expect("ciphersp must decrypt");

    let mut rlsj = [0u8; 32];
    rlsj.copy_from_slice(&pt[0..32]);

    let mut ctr_bytes = [0u8; 8];
    ctr_bytes.copy_from_slice(&pt[32..40]);
    let ctr = u64::from_le_bytes(ctr_bytes);

    let vinfo = up_crypto::hash_vinfo(&rlsj, &fx.lsj);
    acc.update(&ctr.to_le_bytes());
    acc.update(vinfo.as_ref());

    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

fn bench_upspa_client_proto(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    pwdupd_versions: &[u8],
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "upspa";
    let fx = upspa_proto::make_fixture(nsp, tsp);

    let fx_setup = upspa_proto::make_setup_bench_fixture();

    {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_unified/upspa/proto/setup_rng", nsp, tsp));
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let outv = upspa_proto::setup_user_side_bench(&fx_setup, nsp, tsp, &mut rng);
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "proto", "setup", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    let mut rng_reg = ChaCha20Rng::from_seed(seed_for(b"bench_unified/upspa/proto/reg_it", nsp, tsp));
    let mut rng_auth = ChaCha20Rng::from_seed(seed_for(b"bench_unified/upspa/proto/auth_it", nsp, tsp));
    let mut rng_sec = ChaCha20Rng::from_seed(seed_for(b"bench_unified/upspa/proto/sec_it", nsp, tsp));
    let mut rng_pwd = ChaCha20Rng::from_seed(seed_for(b"bench_unified/upspa/proto/pwd_it", nsp, tsp));

    {
        let st = bench_u128(
            || {
                let it = upspa_proto::make_iter_data(&fx, &mut rng_reg);

                let it = it;
                let (rlsj, nonce) = if rng_in_timed {
                    ([0u8; 32], [0u8; up_crypto::NONCE_LEN])
                } else {
                    upspa_precompute_reg_rng_outputs(it.r)
                };

                let t0 = Instant::now();
                let outv = if rng_in_timed {
                    upspa_proto::registration_user_side(&fx, &it)
                } else {
                    upspa_registration_no_rng(&fx, &it, rlsj, nonce)
                };
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "proto", "reg", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    {
        let st = bench_u128(
            || {
                let it = upspa_proto::make_iter_data(&fx, &mut rng_auth);
                let t0 = Instant::now();
                let outv = upspa_auth_two_decryptions(&fx, &it);
                black_box(outv);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(out, scheme, "proto", "auth", rng_in_timed, nsp, tsp, warmup, &st)?;
    }

    {
        let st = bench_u128(
            || {
                let it = upspa_proto::make_iter_data(&fx, &mut rng_sec);
                let (new_rlsj, nonce) = if rng_in_timed {
                    ([0u8; 32], [0u8; up_crypto::NONCE_LEN])
                } else {
                    upspa_precompute_secu_rng_outputs(it.r)
                };

                let t0 = Instant::now();
                let outv = if rng_in_timed {
                    upspa_proto::secret_update_user_side(&fx, &it)
                } else {
                    upspa_secu_no_rng(&fx, &it, new_rlsj, nonce)
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
            "proto",
            "secupd",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    for &v in pwdupd_versions {
        let op_label = if v == 2 { "pwdupd_v2" } else { "pwdupd" };
        let st = bench_u128(
            || {
                let it = upspa_proto::make_iter_data(&fx, &mut rng_pwd);

                let (coeffs, nonce_v1, nonce_v2) = if rng_in_timed {
                    (
                        Vec::new(),
                        [0u8; up_crypto::NONCE_LEN],
                        [0u8; up_crypto::NONCE_LEN],
                    )
                } else {
                    let (coeffs, nonce_v1) = upspa_precompute_pwdupd_coeffs_and_nonce(it.r, fx.tsp);
                    let nonce_v2 = upspa_precompute_pwdupd_v2_nonce(it.r);
                    (coeffs, nonce_v1, nonce_v2)
                };

                let t0 = Instant::now();
                let outv = if rng_in_timed {
                    if v == 2 {
                        upspa_pwdupd_v2_rng_in_timed(&fx, &it, &mut rng_pwd)
                    } else {
                        upspa_proto::password_update_user_side(&fx, &it)
                    }
                } else {
                    if v == 2 {
                        upspa_pwdupd_v2_no_rng(&fx, &it, nonce_v2)
                    } else {
                        upspa_pwdupd_no_rng(&fx, &it, &coeffs, nonce_v1)
                    }
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
            "proto",
            op_label,
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    Ok(())
}

fn bench_upspa_client_prims(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    let scheme = "upspa";
    let fx = upspa_proto::make_fixture(nsp, tsp);

    let mut rng0 = ChaCha20Rng::from_seed(seed_for(b"bench_unified/upspa/prim/derive", nsp, tsp));
    let it0 = upspa_proto::make_iter_data(&fx, &mut rng0);
    let (state_key0, cipherid_pt0) = upspa_recover_state_and_cipherid_pt(&fx, &it0);
    let (rsp0, fk0, _sid0) = upspa_extract_rsp_fk_sid(&cipherid_pt0);

    {
        let mut rng = ChaCha20Rng::from_seed(seed_for(b"bench_unified/upspa/prim/toprf", nsp, tsp));
        let st = bench_u128(
            || {
                let it = upspa_proto::make_iter_data(&fx, &mut rng);
                let t0 = Instant::now();

                let b = &fx.pwd_point * it.r;
                black_box(b);

                let k = up_crypto::toprf_client_eval_from_partials(
                    &fx.password,
                    it.r,
                    &it.partials,
                    &fx.lagrange_at_zero,
                );
                black_box(k);

                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "TOPRF_recv_eval_tsp",
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
                let pt =
                    up_crypto::xchacha_decrypt_detached(&state_key0, &fx.cipherid_aad, &fx.cipherid).unwrap();
                black_box(pt);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "AEAD_DEC_cipherid",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let one = &fx.ciphersp_per_sp[0];
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let pt = up_crypto::xchacha_decrypt_detached(&fk0, &fx.ciphersp_aad, one).unwrap();
                black_box(pt);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "prim",
            "AEAD_DEC_ciphersp",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    {
        let ctr: u64 = 0;
        let mut pt = [0u8; upspa_proto::CIPHERSP_PT_LEN];
        pt[0..32].copy_from_slice(&fx.cached_rlsj);
        pt[32..40].copy_from_slice(&ctr.to_le_bytes());

        if rng_in_timed {
            let mut rng =
                ChaCha20Rng::from_seed(seed_for(b"bench_unified/upspa/prim/aead_enc_rng", nsp, tsp));
            let st = bench_u128(
                || {
                    let t0 = Instant::now();
                    let c = up_crypto::xchacha_encrypt_detached(&fk0, &fx.ciphersp_aad, &pt, &mut rng);
                    black_box(c.ct);
                    black_box(c.tag);
                    t0.elapsed().as_nanos()
                },
                warmup,
                samples,
            );
            write_row(
                out,
                scheme,
                "prim",
                "AEAD_ENC_ciphersp_with_rng",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &st,
            )?;
        } else {
            let nonce = [0x42u8; up_crypto::NONCE_LEN];
            let st = bench_u128(
                || {
                    let t0 = Instant::now();
                    let c = upspa_aead_encrypt_fixed(&fk0, &fx.ciphersp_aad, &pt, nonce);
                    black_box(c.ct);
                    black_box(c.tag);
                    t0.elapsed().as_nanos()
                },
                warmup,
                samples,
            );
            write_row(
                out,
                scheme,
                "prim",
                "AEAD_ENC_ciphersp_fixed_nonce",
                rng_in_timed,
                nsp,
                tsp,
                warmup,
                &st,
            )?;
        }
    }

    {
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let h = up_crypto::hash_suid(&rsp0, &fx.lsj, 1);
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
            "HASH_suid",
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
                let h = up_crypto::hash_vinfo(&fx.cached_rlsj, &fx.lsj);
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
            "HASH_vinfo",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    Ok(())
}

fn upspa_pwdupd_v2_rng_in_timed(
    fx: &upspa_proto::Fixture,
    it: &upspa_proto::IterData,
    rng: &mut ChaCha20Rng,
) -> [u8; 32] {
    let (_state_key, cipherid_pt) = upspa_recover_state_and_cipherid_pt(fx, it);
    let (_rsp, _fk, sid) = upspa_extract_rsp_fk_sid(&cipherid_pt);

    let p_new = up_crypto::hash_to_point(&fx.new_password);
    let blinded_new = p_new * it.r;
    black_box(blinded_new);

    let mut partials_new: Vec<RistrettoPoint> = Vec::with_capacity(fx.tsp);
    for &id in fx.ids_for_t.iter() {
        let share = fx.shares[(id - 1) as usize].1;
        partials_new.push(blinded_new * share);
    }

    let new_state_key = up_crypto::toprf_client_eval_from_partials(
        &fx.new_password,
        it.r,
        &partials_new,
        &fx.lagrange_at_zero,
    );

    let mut nonce = [0u8; up_crypto::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let newcipherid = upspa_aead_encrypt_fixed(&new_state_key, &fx.cipherid_aad, &cipherid_pt, nonce);

    let timestamp: u64 = 0;
    const MSG_LEN: usize = 24 + 96 + 16 + 8;
    let mut msg = [0u8; MSG_LEN];
    let mut off = 0;
    msg[off..off + 24].copy_from_slice(&newcipherid.nonce);
    off += 24;
    msg[off..off + 96].copy_from_slice(&newcipherid.ct);
    off += 96;
    msg[off..off + 16].copy_from_slice(&newcipherid.tag);
    off += 16;
    msg[off..off + 8].copy_from_slice(&timestamp.to_le_bytes());
    off += 8;
    debug_assert_eq!(off, MSG_LEN);

    let sig = sid.sign(&msg);
    let sig_bytes = sig.to_bytes();

    let mut acc = blake3::Hasher::new();
    acc.update(b"uptspa/password_update/acc/v2_rng_in_timed");
    acc.update(&sig_bytes);
    acc.update(&newcipherid.nonce);
    acc.update(&newcipherid.ct);
    acc.update(&newcipherid.tag);
    let out = acc.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

fn bench_upspa_server_prims(
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    pwdupd_versions: &[u8],
    rng_in_timed: bool,
    out: &mut BufWriter<File>,
) -> std::io::Result<()> {
    use ed25519_dalek::{Signature, Verifier};

    let scheme = "upspa";
    let fx = upspa_proto::make_fixture(nsp, tsp);

    let seed = seed_for(b"bench_unified/sp/upspa/recover", nsp, tsp);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let r = up_crypto::random_scalar(&mut rng);
    let blinded = fx.pwd_point * r;

    let mut partials = Vec::with_capacity(fx.tsp);
    for id in 1..=fx.tsp {
        let share = fx.shares[id - 1].1;
        partials.push(blinded * share);
    }

    let state_key =
        up_crypto::toprf_client_eval_from_partials(&fx.password, r, &partials, &fx.lagrange_at_zero);

    let cipherid_pt = up_crypto::xchacha_decrypt_detached(&state_key, &fx.cipherid_aad, &fx.cipherid)
        .expect("cipherid must decrypt");

    let mut sid_bytes = [0u8; 32];
    sid_bytes.copy_from_slice(&cipherid_pt[0..32]);
    let sid = SigningKey::from_bytes(&sid_bytes);

    let mut rsp = [0u8; 32];
    rsp.copy_from_slice(&cipherid_pt[32..64]);

    let mut providers = Vec::with_capacity(fx.nsp);
    for i in 1..=fx.nsp {
        let share = fx.shares[i - 1].1;
        let mut sp = sp_mod::UpSpaProvider::new(i as u32, share, fx.sig_pk_bytes, fx.cipherid.clone());
        let suid = up_crypto::hash_suid(&rsp, &fx.lsj, i as u32);
        sp.put_ciphersp(suid, fx.ciphersp_per_sp[i - 1].clone());
        providers.push(sp);
    }

    let seed = seed_for(b"bench_unified/sp/upspa/blinded", nsp, tsp);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let r = up_crypto::random_scalar(&mut rng);
    let blinded = fx.pwd_point * r;
    let blinded_bytes = sp_mod::compress_point(&blinded);
    black_box(blinded_bytes);

    let suid_1 = up_crypto::hash_suid(&rsp, &fx.lsj, 1);
    let csp_blob = fx.ciphersp_per_sp[0].clone();

    {
        let st = bench_u128(
            || {
                let t0 = Instant::now();
                let y = providers[0].toprf_send_eval(&blinded_bytes);
                black_box(y);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "sp",
            "srv_TOPRF_send_eval_one",
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
                let v = providers[0].get_ciphersp(&suid_1);
                black_box(v);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "sp",
            "srv_DB_get_ciphersp_one",
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
                providers[0].put_ciphersp(suid_1, csp_blob.clone());
                black_box(&providers[0]);
                t0.elapsed().as_nanos()
            },
            warmup,
            samples,
        );
        write_row(
            out,
            scheme,
            "sp",
            "srv_DB_put_ciphersp_one",
            rng_in_timed,
            nsp,
            tsp,
            warmup,
            &st,
        )?;
    }

    for &v in pwdupd_versions {
        if v == 2 {
            const MSG_LEN_V2: usize = 24 + upspa_proto::CIPHERID_PT_LEN + 16 + 8;
            let mut msg = [0u8; MSG_LEN_V2];
            let mut off = 0;
            msg[off..off + 24].copy_from_slice(&fx.cipherid.nonce);
            off += 24;
            msg[off..off + upspa_proto::CIPHERID_PT_LEN].copy_from_slice(&fx.cipherid.ct);
            off += upspa_proto::CIPHERID_PT_LEN;
            msg[off..off + 16].copy_from_slice(&fx.cipherid.tag);
            off += 16;
            msg[off..off + 8].copy_from_slice(&0u64.to_le_bytes());
            off += 8;
            debug_assert_eq!(off, MSG_LEN_V2);

            let sig: Signature = sid.sign(&msg);

            {
                let st = bench_u128(
                    || {
                        let t0 = Instant::now();
                        let ok = providers[0].sig_pk.verify(&msg, &sig).is_ok();
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
                    "srv_Ed25519_verify_pwdupd_v2_one",
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
                        let ok = providers[0].sig_pk.verify(&msg, &sig).is_ok();
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
                    "srv_PWDUPD_v2_verify_only_one",
                    rng_in_timed,
                    nsp,
                    tsp,
                    warmup,
                    &st,
                )?;
            }
        } else {
            let mut rng2 =
                ChaCha20Rng::from_seed(seed_for(b"bench_unified/sp/upspa/pwdupd_v1_gen", nsp, tsp));
            let (_new_master_sk, new_shares) = up_crypto::toprf_gen(fx.nsp, fx.tsp, &mut rng2);

            const MSG_LEN_V1: usize = 24 + upspa_proto::CIPHERID_PT_LEN + 16 + 32 + 8 + 4;
            let (spid1, share1) = new_shares[0];
            let mut msg = [0u8; MSG_LEN_V1];
            let mut off = 0;
            msg[off..off + 24].copy_from_slice(&fx.cipherid.nonce);
            off += 24;
            msg[off..off + upspa_proto::CIPHERID_PT_LEN].copy_from_slice(&fx.cipherid.ct);
            off += upspa_proto::CIPHERID_PT_LEN;
            msg[off..off + 16].copy_from_slice(&fx.cipherid.tag);
            off += 16;
            msg[off..off + 32].copy_from_slice(&share1.to_bytes());
            off += 32;
            msg[off..off + 8].copy_from_slice(&0u64.to_le_bytes());
            off += 8;
            msg[off..off + 4].copy_from_slice(&spid1.to_le_bytes());
            off += 4;
            debug_assert_eq!(off, MSG_LEN_V1);

            let sig: Signature = sid.sign(&msg);

            {
                let st = bench_u128(
                    || {
                        let t0 = Instant::now();
                        let ok = providers[0].sig_pk.verify(&msg, &sig).is_ok();
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
                    "srv_Ed25519_verify_pwdupd_v1_one",
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
                        let ok = providers[0].apply_password_update(&msg, &sig);
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
                    "srv_PWDUPD_v1_apply_one",
                    rng_in_timed,
                    nsp,
                    tsp,
                    warmup,
                    &st,
                )?;
            }
        }
    }

    Ok(())
}

fn upspa_pwdupd_req_bytes(version: u8) -> usize {
    if version == 2 {
        64 + 24 + upspa_proto::CIPHERID_PT_LEN + 16 + 8
    } else {
        sp_mod::NET_UPSPA_PWDUPD_REQ_BYTES
    }
}

fn net_upspa_setup(nsp: usize, prof: NetProfile, proc_ns: u64, rng: &mut impl RngCore) -> u64 {
    simulate_parallel_phase(
        nsp,
        sp_mod::NET_UPSPA_SETUP_REQ_BYTES,
        sp_mod::NET_UPSPA_SETUP_RESP_BYTES,
        proc_ns,
        prof,
        rng,
    )
}

fn net_upspa_auth(
    nsp: usize,
    tsp: usize,
    prof: NetProfile,
    proc_toprf: u64,
    proc_db_get: u64,
    rng: &mut impl RngCore,
) -> u64 {
    let m = (nsp + tsp - 1) / tsp;
    let p1 = simulate_parallel_phase(
        tsp,
        sp_mod::NET_UPSPA_TOPRF_REQ_BYTES,
        sp_mod::NET_UPSPA_TOPRF_RESP_BYTES,
        proc_toprf,
        prof,
        rng,
    );
    let p2 = simulate_parallel_phase(
        m,
        sp_mod::NET_UPSPA_GET_CSP_REQ_BYTES,
        sp_mod::NET_UPSPA_GET_CSP_RESP_BYTES,
        proc_db_get,
        prof,
        rng,
    );
    p1 + p2
}

fn net_upspa_reg(
    nsp: usize,
    tsp: usize,
    prof: NetProfile,
    proc_toprf: u64,
    proc_db_put: u64,
    rng: &mut impl RngCore,
) -> u64 {
    let p1 = simulate_parallel_phase(
        tsp,
        sp_mod::NET_UPSPA_TOPRF_REQ_BYTES,
        sp_mod::NET_UPSPA_TOPRF_RESP_BYTES,
        proc_toprf,
        prof,
        rng,
    );
    let p2 = simulate_parallel_phase(
        nsp,
        sp_mod::NET_UPSPA_PUT_CSP_REQ_BYTES,
        sp_mod::NET_UPSPA_PUT_CSP_RESP_BYTES,
        proc_db_put,
        prof,
        rng,
    );
    p1 + p2
}

fn net_upspa_secu(
    nsp: usize,
    tsp: usize,
    prof: NetProfile,
    proc_toprf: u64,
    proc_db_get: u64,
    proc_db_put: u64,
    rng: &mut impl RngCore,
) -> u64 {
    let m = (nsp + tsp - 1) / tsp;
    let p1 = simulate_parallel_phase(
        tsp,
        sp_mod::NET_UPSPA_TOPRF_REQ_BYTES,
        sp_mod::NET_UPSPA_TOPRF_RESP_BYTES,
        proc_toprf,
        prof,
        rng,
    );
    let p2 = simulate_parallel_phase(
        m,
        sp_mod::NET_UPSPA_GET_CSP_REQ_BYTES,
        sp_mod::NET_UPSPA_GET_CSP_RESP_BYTES,
        proc_db_get,
        prof,
        rng,
    );
    let p3 = simulate_parallel_phase(
        nsp,
        sp_mod::NET_UPSPA_PUT_CSP_REQ_BYTES,
        sp_mod::NET_UPSPA_PUT_CSP_RESP_BYTES,
        proc_db_put,
        prof,
        rng,
    );
    p1 + p2 + p3
}

fn net_upspa_pwdupd(
    nsp: usize,
    tsp: usize,
    prof: NetProfile,
    version: u8,
    proc_toprf: u64,
    proc_apply: u64,
    rng: &mut impl RngCore,
) -> u64 {
    let p1 = simulate_parallel_phase(
        tsp,
        sp_mod::NET_UPSPA_TOPRF_REQ_BYTES,
        sp_mod::NET_UPSPA_TOPRF_RESP_BYTES,
        proc_toprf,
        prof,
        rng,
    );
    let p2 = simulate_parallel_phase(
        nsp,
        upspa_pwdupd_req_bytes(version),
        sp_mod::NET_UPSPA_PWDUPD_RESP_BYTES,
        proc_apply,
        prof,
        rng,
    );
    p1 + p2
}

fn bench_net_phase(
    out: &mut BufWriter<File>,
    scheme: &str,
    op_name: &str,
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    prof: NetProfile,
    rng_in_timed: bool,
    mut net_f: impl FnMut(&mut ChaCha20Rng) -> u64,
) -> std::io::Result<()> {
    let mut tag = Vec::new();
    tag.extend_from_slice(b"bench_unified/net/");
    tag.extend_from_slice(scheme.as_bytes());
    tag.extend_from_slice(b"/");
    tag.extend_from_slice(op_name.as_bytes());
    tag.extend_from_slice(b"/");
    tag.extend_from_slice(prof.name.as_bytes());
    let seed = seed_for(&tag, nsp, tsp);
    let mut rng = ChaCha20Rng::from_seed(seed);

    for _ in 0..warmup {
        let net = net_f(&mut rng);
        black_box(net);
    }

    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        let net = net_f(&mut rng);
        xs.push(net as u128);
    }

    let st = compute_stats(xs);
    let op = format!("{}_{}_net", prof.name, op_name);
    write_row(out, scheme, "net", &op, rng_in_timed, nsp, tsp, warmup, &st)
}

fn bench_full_phase(
    out: &mut BufWriter<File>,
    scheme: &str,
    op_name: &str,
    nsp: usize,
    tsp: usize,
    warmup: usize,
    samples: usize,
    prof: NetProfile,
    rng_in_timed: bool,
    mut client_f: impl FnMut() -> u64,
    mut net_f: impl FnMut(&mut ChaCha20Rng) -> u64,
) -> std::io::Result<()> {
    let mut tag = Vec::new();
    tag.extend_from_slice(b"bench_unified/full/");
    tag.extend_from_slice(scheme.as_bytes());
    tag.extend_from_slice(b"/");
    tag.extend_from_slice(op_name.as_bytes());
    tag.extend_from_slice(b"/");
    tag.extend_from_slice(prof.name.as_bytes());
    let seed = seed_for(&tag, nsp, tsp);
    let mut rng = ChaCha20Rng::from_seed(seed);

    for _ in 0..warmup {
        let c = client_f();
        let net = net_f(&mut rng);
        black_box(c);
        black_box(net);
    }

    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        let c = client_f();
        let net = net_f(&mut rng);
        xs.push((c as u128) + (net as u128));
    }

    let st = compute_stats(xs);
    let op = format!("{}_{}_total", prof.name, op_name);
    write_row(out, scheme, "full", &op, rng_in_timed, nsp, tsp, warmup, &st)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PwdupdMode {
    V1,
    V2,
    Both,
}

#[derive(Clone, Debug)]
struct Config {
    scheme: String,
    kinds: Vec<String>,
    net_sel: String,
    pwdupd_mode: PwdupdMode,

    nsp_list: Vec<usize>,
    tsp_abs: Option<Vec<usize>>,
    tsp_pct: Option<Vec<u32>>,

    sample_size: usize,
    warmup_iters: usize,
    out_path: String,
    rng_in_timed: bool,

    lan_rtt_ms: f64,
    lan_jitter_ms: f64,
    lan_bw_mbps: f64,
    wan_rtt_ms: f64,
    wan_jitter_ms: f64,
    wan_bw_mbps: f64,
    overhead_bytes: usize,

    proc_warmup: usize,
    proc_samples: usize,
}

fn print_help() {
    eprintln!(
        r#"bench_unified (unified bench for tspa/upspa)

USAGE:
  bench_unified [FLAGS]

CORE FLAGS:
  --scheme all|upspa|tspa          Which scheme(s) to benchmark (default: all)
  --kind  proto,prim,sp,net,full   Which benchmark kinds to run (default: proto,prim)
                                   Use "all" to run everything.
  --pwdupd 1|2|both|v1|v2          Password-update variant(s) (default: 1)
  --out FILE                       Output file (default: unified_bench.dat)

GRID FLAGS:
  --nsp 20,40,60,80,100            nsp values (default shown)
  --tsp 5,10,20                    tsp absolute values (overrides --tsp-pct)
  --tsp-pct 20,40,60,80,100        tsp as percent of nsp (rounded up; default shown)

TIMING FLAGS:
  --sample-size N                  Samples per op (default: 2000)
  --warmup-iters N                 Warmup iterations per op (default: 300)
  --rng-in-timed                   Keep RNG work inside timed region where applicable

NETWORK FLAGS (used by --kind net and/or --kind full):
  --net lan|wan|all                Which network profiles (default: all)
  --lan-rtt-ms X --lan-jitter-ms Y --lan-bw-mbps Z
  --wan-rtt-ms X --wan-jitter-ms Y --wan-bw-mbps Z
  --overhead-bytes N               Per-message overhead bytes (default: 64)

SERVER P50 CALIBRATION (only used by --kind full):
  --proc-warmup N                  Warmup for server p50 microbench (default: 200)
  --proc-samples N                 Samples for server p50 microbench (default: 1000)

EXAMPLES:
  # Client-only protocol phases, pwdupd v2
  bench_unified --scheme upspa --kind proto --pwdupd v2

  # Full end-to-end (client + net + server p50), WAN only, pwdupd v2
  bench_unified --scheme upspa --kind full --net wan --pwdupd v2

  # Net-only simulation, LAN+WAN
  bench_unified --scheme upspa --kind net --net all

  # Server-only primitives (UpSPA + TSPA)
  bench_unified --scheme all --kind sp

"#
    );
}

fn parse_args(input: Vec<String>) -> Config {
    let mut cfg = Config {
        scheme: "all".to_string(),
        kinds: vec!["proto".to_string(), "prim".to_string()],
        net_sel: "all".to_string(),
        pwdupd_mode: PwdupdMode::V1,

        nsp_list: vec![20, 40, 60, 80, 100],
        tsp_abs: None,
        tsp_pct: Some(vec![20, 40, 60, 80, 100]),

        sample_size: 200,
        warmup_iters: 50,
        out_path: "unified_bench.dat".to_string(),
        rng_in_timed: false,

        lan_rtt_ms: 0.5,
        lan_jitter_ms: 0.05,
        lan_bw_mbps: 1000.0,

        wan_rtt_ms: 60.0,
        wan_jitter_ms: 5.0,
        wan_bw_mbps: 50.0,

        overhead_bytes: 64,

        proc_warmup: 200,
        proc_samples: 1000,
    };

    let mut args = input.into_iter();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--scheme" => cfg.scheme = args.next().expect("missing --scheme value"),
            "--kind" => {
                let v = args.next().expect("missing --kind value");
                let ks = parse_list_string_lower(&v);
                if ks.iter().any(|k| k == "all") {
                    cfg.kinds = vec![
                        "proto".into(),
                        "prim".into(),
                        "sp".into(),
                        "net".into(),
                        "full".into(),
                    ];
                } else {
                    cfg.kinds = ks;
                }
            }
            "--pwdupd" => {
                let v = args.next().expect("missing --pwdupd value").to_ascii_lowercase();
                cfg.pwdupd_mode = match v.as_str() {
                    "1" | "v1" => PwdupdMode::V1,
                    "2" | "v2" => PwdupdMode::V2,
                    "both" | "all" => PwdupdMode::Both,
                    _ => panic!("invalid --pwdupd value (use 1|2|both or v1|v2)"),
                };
            }
            "--pwdupd-v2" => cfg.pwdupd_mode = PwdupdMode::V2,

            "--net" => cfg.net_sel = args.next().expect("missing --net value"),
            "--nsp" => cfg.nsp_list = parse_list_usize(&args.next().expect("missing --nsp value")),
            "--tsp" => {
                cfg.tsp_abs = Some(parse_list_usize(&args.next().expect("missing --tsp value")));
                cfg.tsp_pct = None;
            }
            "--tsp-pct" => {
                cfg.tsp_pct = Some(parse_list_u32(&args.next().expect("missing --tsp-pct value")));
                cfg.tsp_abs = None;
            }

            "--sample-size" => cfg.sample_size = args.next().expect("missing --sample-size").parse().unwrap(),
            "--warmup-iters" => {
                cfg.warmup_iters = args.next().expect("missing --warmup-iters").parse().unwrap()
            }
            "--out" => cfg.out_path = args.next().expect("missing --out"),
            "--rng-in-timed" | "--rng" => cfg.rng_in_timed = true,

            "--lan-rtt-ms" => cfg.lan_rtt_ms = args.next().expect("missing --lan-rtt-ms").parse().unwrap(),
            "--lan-jitter-ms" => {
                cfg.lan_jitter_ms = args.next().expect("missing --lan-jitter-ms").parse().unwrap()
            }
            "--lan-bw-mbps" => cfg.lan_bw_mbps = args.next().expect("missing --lan-bw-mbps").parse().unwrap(),
            "--wan-rtt-ms" => cfg.wan_rtt_ms = args.next().expect("missing --wan-rtt-ms").parse().unwrap(),
            "--wan-jitter-ms" => {
                cfg.wan_jitter_ms = args.next().expect("missing --wan-jitter-ms").parse().unwrap()
            }
            "--wan-bw-mbps" => cfg.wan_bw_mbps = args.next().expect("missing --wan-bw-mbps").parse().unwrap(),
            "--overhead-bytes" => {
                cfg.overhead_bytes = args.next().expect("missing --overhead-bytes").parse().unwrap()
            }

            "--proc-warmup" => cfg.proc_warmup = args.next().expect("missing --proc-warmup").parse().unwrap(),
            "--proc-samples" => {
                cfg.proc_samples = args.next().expect("missing --proc-samples").parse().unwrap()
            }

            "--bench" => {
                let _ = args.next();
            }
            _ if a.starts_with('-') => {}
            _ => {}
        }
    }

    cfg
}

pub fn run(args: Vec<String>) -> std::io::Result<()> {
    let cfg = parse_args(args);

    let do_proto = cfg.kinds.iter().any(|k| k == "proto");
    let do_prim = cfg.kinds.iter().any(|k| k == "prim");
    let do_sp = cfg.kinds.iter().any(|k| k == "sp");
    let do_net = cfg.kinds.iter().any(|k| k == "net");
    let do_full = cfg.kinds.iter().any(|k| k == "full");

    let pwdupd_versions: Vec<u8> = match cfg.pwdupd_mode {
        PwdupdMode::V1 => vec![1],
        PwdupdMode::V2 => vec![2],
        PwdupdMode::Both => vec![1, 2],
    };

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

    let mut profiles: Vec<NetProfile> = Vec::new();
    match cfg.net_sel.as_str() {
        "lan" => profiles.push(lan),
        "wan" => profiles.push(wan),
        _ => {
            profiles.push(lan);
            profiles.push(wan);
        }
    }

    let file = File::create(&cfg.out_path)?;
    let mut out = BufWriter::new(file);
    write_header(&mut out)?;

    for &nsp in &cfg.nsp_list {
        let tsp_list: Vec<usize> = if let Some(ts) = &cfg.tsp_abs {
            ts.clone()
        } else {
            let pcts = cfg.tsp_pct.as_ref().unwrap();
            pcts.iter()
                .map(|p| {
                    let v = ((nsp as u128) * (*p as u128) + 99) / 100;
                    let v = v as usize;
                    v.clamp(1, nsp)
                })
                .collect()
        };

        for &tsp in &tsp_list {
            let procs = if do_full {
                Some(measure_server_procs_p50(
                    nsp,
                    tsp,
                    cfg.proc_warmup,
                    cfg.proc_samples,
                ))
            } else {
                None
            };

            if cfg.scheme == "all" || cfg.scheme == "upspa" {
                if do_proto {
                    bench_upspa_client_proto(
                        nsp,
                        tsp,
                        cfg.warmup_iters,
                        cfg.sample_size,
                        &pwdupd_versions,
                        cfg.rng_in_timed,
                        &mut out,
                    )?;
                }
                if do_prim {
                    bench_upspa_client_prims(
                        nsp,
                        tsp,
                        cfg.warmup_iters,
                        cfg.sample_size,
                        cfg.rng_in_timed,
                        &mut out,
                    )?;
                }
                if do_sp {
                    bench_upspa_server_prims(
                        nsp,
                        tsp,
                        cfg.warmup_iters,
                        cfg.sample_size,
                        &pwdupd_versions,
                        cfg.rng_in_timed,
                        &mut out,
                    )?;
                }

                if do_net {
                    for prof in &profiles {
                        bench_net_phase(
                            &mut out,
                            "upspa",
                            "setup",
                            nsp,
                            tsp,
                            cfg.warmup_iters,
                            cfg.sample_size,
                            *prof,
                            cfg.rng_in_timed,
                            |r| net_upspa_setup(nsp, *prof, 0, r),
                        )?;
                        bench_net_phase(
                            &mut out,
                            "upspa",
                            "reg",
                            nsp,
                            tsp,
                            cfg.warmup_iters,
                            cfg.sample_size,
                            *prof,
                            cfg.rng_in_timed,
                            |r| net_upspa_reg(nsp, tsp, *prof, 0, 0, r),
                        )?;
                        bench_net_phase(
                            &mut out,
                            "upspa",
                            "auth",
                            nsp,
                            tsp,
                            cfg.warmup_iters,
                            cfg.sample_size,
                            *prof,
                            cfg.rng_in_timed,
                            |r| net_upspa_auth(nsp, tsp, *prof, 0, 0, r),
                        )?;
                        bench_net_phase(
                            &mut out,
                            "upspa",
                            "secupd",
                            nsp,
                            tsp,
                            cfg.warmup_iters,
                            cfg.sample_size,
                            *prof,
                            cfg.rng_in_timed,
                            |r| net_upspa_secu(nsp, tsp, *prof, 0, 0, 0, r),
                        )?;
                        for &v in &pwdupd_versions {
                            let op = if v == 2 { "pwdupd_v2" } else { "pwdupd" };
                            bench_net_phase(
                                &mut out,
                                "upspa",
                                op,
                                nsp,
                                tsp,
                                cfg.warmup_iters,
                                cfg.sample_size,
                                *prof,
                                cfg.rng_in_timed,
                                |r| net_upspa_pwdupd(nsp, tsp, *prof, v, 0, 0, r),
                            )?;
                        }
                    }
                }

                if do_full {
                    let procs = procs.unwrap();

                    let fx_up = upspa_proto::make_fixture(nsp, tsp);
                    let fx_up_setup = upspa_proto::make_setup_bench_fixture();

                    let seed_it = seed_for(b"bench_unified/full/it_seed", nsp, tsp);
                    let mut it_rng = ChaCha20Rng::from_seed(seed_it);

                    let it_up_auth = upspa_proto::make_iter_data(&fx_up, &mut it_rng);
                    let it_up_reg = upspa_proto::make_iter_data(&fx_up, &mut it_rng);
                    let it_up_secu = upspa_proto::make_iter_data(&fx_up, &mut it_rng);
                    let it_up_pwdupd = upspa_proto::make_iter_data(&fx_up, &mut it_rng);

                    let up_client_setup = || {
                        let seed = seed_for(b"bench_unified/full/up_setup_rng", nsp, tsp);
                        let mut rng = ChaCha20Rng::from_seed(seed);
                        time_call_ns(|| upspa_proto::setup_user_side_bench(&fx_up_setup, nsp, tsp, &mut rng))
                    };
                    let up_client_reg =
                        || time_call_ns(|| upspa_proto::registration_user_side(&fx_up, &it_up_reg));
                    let up_client_auth = || time_call_ns(|| upspa_auth_two_decryptions(&fx_up, &it_up_auth));
                    let up_client_secu =
                        || time_call_ns(|| upspa_proto::secret_update_user_side(&fx_up, &it_up_secu));

                    for prof in &profiles {
                        bench_full_phase(
                            &mut out,
                            "upspa",
                            "setup",
                            nsp,
                            tsp,
                            cfg.warmup_iters,
                            cfg.sample_size,
                            *prof,
                            cfg.rng_in_timed,
                            up_client_setup,
                            |r| net_upspa_setup(nsp, *prof, procs.up_setup_store_ns, r),
                        )?;

                        bench_full_phase(
                            &mut out,
                            "upspa",
                            "reg",
                            nsp,
                            tsp,
                            cfg.warmup_iters,
                            cfg.sample_size,
                            *prof,
                            cfg.rng_in_timed,
                            up_client_reg,
                            |r| net_upspa_reg(nsp, tsp, *prof, procs.up_toprf_eval_ns, procs.up_db_put_ns, r),
                        )?;

                        bench_full_phase(
                            &mut out,
                            "upspa",
                            "auth",
                            nsp,
                            tsp,
                            cfg.warmup_iters,
                            cfg.sample_size,
                            *prof,
                            cfg.rng_in_timed,
                            up_client_auth,
                            |r| {
                                net_upspa_auth(nsp, tsp, *prof, procs.up_toprf_eval_ns, procs.up_db_get_ns, r)
                            },
                        )?;

                        bench_full_phase(
                            &mut out,
                            "upspa",
                            "secupd",
                            nsp,
                            tsp,
                            cfg.warmup_iters,
                            cfg.sample_size,
                            *prof,
                            cfg.rng_in_timed,
                            up_client_secu,
                            |r| {
                                net_upspa_secu(
                                    nsp,
                                    tsp,
                                    *prof,
                                    procs.up_toprf_eval_ns,
                                    procs.up_db_get_ns,
                                    procs.up_db_put_ns,
                                    r,
                                )
                            },
                        )?;

                        for &v in &pwdupd_versions {
                            let op = if v == 2 { "pwdupd_v2" } else { "pwdupd" };
                            let proc_apply = if v == 2 {
                                procs.up_pwdupd_apply_ns_v2
                            } else {
                                procs.up_pwdupd_apply_ns_v1
                            };
                            let up_client_pwdupd = || {
                                if v == 2 {
                                    time_call_ns(|| {
                                        let nonce = upspa_precompute_pwdupd_v2_nonce(it_up_pwdupd.r);
                                        upspa_pwdupd_v2_no_rng(&fx_up, &it_up_pwdupd, nonce)
                                    })
                                } else {
                                    time_call_ns(|| {
                                        upspa_proto::password_update_user_side(&fx_up, &it_up_pwdupd)
                                    })
                                }
                            };
                            bench_full_phase(
                                &mut out,
                                "upspa",
                                op,
                                nsp,
                                tsp,
                                cfg.warmup_iters,
                                cfg.sample_size,
                                *prof,
                                cfg.rng_in_timed,
                                up_client_pwdupd,
                                |r| {
                                    net_upspa_pwdupd(
                                        nsp,
                                        tsp,
                                        *prof,
                                        v,
                                        procs.up_toprf_eval_ns,
                                        proc_apply,
                                        r,
                                    )
                                },
                            )?;
                        }
                    }
                }
            }

            out.flush()?;
            eprintln!(
                "done nsp={nsp} tsp={tsp} scheme={} kinds={:?} pwdupd={:?} net={} rng_in_timed={}",
                cfg.scheme, cfg.kinds, cfg.pwdupd_mode, cfg.net_sel, cfg.rng_in_timed
            );
        }
    }

    Ok(())
}
