use std::{
    env,
    fs::{self, File},
    io::{self, BufWriter, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use num_bigint::BigUint;
use pastau_paper::{paper_crypto::*, protocol};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const CMD_TOPRF: u8 = 1;
const CMD_TOKEN: u8 = 2;
const CMD_UPDATE: u8 = 3;
const CMD_RESET: u8 = 4;
const CMD_SHUTDOWN: u8 = 5;

#[derive(Debug)]
struct Stats {
    n: usize,
    min: u128,
    p50: u128,
    p95: u128,
    max: u128,
    mean: f64,
    stddev: f64,
}

fn stats(mut xs: Vec<u128>) -> Stats {
    assert!(!xs.is_empty());
    xs.sort_unstable();
    let n = xs.len();
    let mean = xs.iter().map(|&x| x as f64).sum::<f64>() / n as f64;
    let stddev = if n > 1 {
        (xs.iter()
            .map(|&x| {
                let d = x as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / (n - 1) as f64)
            .sqrt()
    } else {
        0.0
    };
    Stats {
        n,
        min: xs[0],
        p50: xs[n / 2],
        p95: xs[(n * 95) / 100],
        max: xs[n - 1],
        mean,
        stddev,
    }
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn arg_usize(args: &[String], name: &str, default: usize) -> usize {
    arg(args, name).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take_bytes<'a>(input: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    if input.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "missing length"));
    }
    let len = u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;
    *input = &input[4..];
    if input.len() < len {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short field"));
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Ok(value)
}

fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()
}

fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let mut bytes = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn exchange(stream: &TcpStream, request: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut stream = stream.try_clone()?;
    write_frame(&mut stream, &request)?;
    read_frame(&mut stream)
}

fn parallel_exchange(streams: &[TcpStream], requests: Vec<Vec<u8>>) -> io::Result<Vec<Vec<u8>>> {
    if streams.len() != requests.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stream/request mismatch",
        ));
    }
    thread::scope(|scope| {
        let handles: Vec<_> = streams
            .iter()
            .zip(requests)
            .map(|(stream, request)| scope.spawn(move || exchange(stream, request)))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .map_err(|_| io::Error::other("request thread panicked"))?
            })
            .collect()
    })
}

fn load_or_create_setup(path: &Path, n: usize, t: usize) -> Result<ShoupSetup, Box<dyn std::error::Error>> {
    if path.exists() {
        return Ok(serde_json::from_slice(&fs::read(path)?)?);
    }
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let setup = shoup_setup(n, t, &mut rng)?;
    fs::write(path, serde_json::to_vec(&setup)?)?;
    Ok(setup)
}

fn fixture(n: usize, t: usize, setup: ShoupSetup) -> Result<protocol::Fixture, CryptoError> {
    let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
    protocol::setup_fixture_with_ttg(n, t, setup, &mut rng)
}

fn encode_response(resp: &protocol::TokenResponse) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&resp.id.to_be_bytes());
    put_bytes(&mut out, &resp.z_i.to_bytes_be());
    put_bytes(&mut out, &resp.encrypted_partial);
    out.extend_from_slice(&resp.iv);
    out
}

fn decode_response(bytes: &[u8]) -> io::Result<protocol::TokenResponse> {
    if bytes.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short token response"));
    }
    let id = u32::from_be_bytes(bytes[..4].try_into().unwrap());
    let mut input = &bytes[4..];
    let z_i = BigUint::from_bytes_be(take_bytes(&mut input)?);
    let encrypted_partial = take_bytes(&mut input)?.to_vec();
    if input.len() != 16 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad IV length"));
    }
    let iv = input.try_into().unwrap();
    Ok(protocol::TokenResponse {
        id,
        z_i,
        encrypted_partial,
        iv,
    })
}

fn signed_message(payload: &[u8], client_id: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + client_id.len());
    out.extend_from_slice(payload);
    out.extend_from_slice(client_id);
    out
}

fn server_main(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let n = arg_usize(args, "--n", 3);
    let t = arg_usize(args, "--t", 2);
    let id = arg_usize(args, "--id", 1);
    let port = arg_usize(args, "--port", 0);
    let setup_path = PathBuf::from(arg(args, "--setup-file").ok_or("--setup-file is required")?);
    let fx = fixture(n, t, load_or_create_setup(&setup_path, n, t)?)?;
    let template = fx.servers[id - 1].clone();
    let mut server = template.clone();
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(id as u64).to_le_bytes());
    seed[8..16].copy_from_slice(&(n as u64).to_le_bytes());
    seed[16..24].copy_from_slice(&(t as u64).to_le_bytes());
    let mut rng = ChaCha20Rng::from_seed(seed);
    let listener = TcpListener::bind(("127.0.0.1", port as u16))?;
    let (mut stream, _) = listener.accept()?;
    stream.set_nodelay(true)?;

    while let Ok(frame) = read_frame(&mut stream) {
        if frame.is_empty() {
            return Err("empty command".into());
        }
        let reply = match frame[0] {
            CMD_TOPRF => {
                let encoded = BigUint::from_bytes_be(&frame[1..]);
                toprf_eval(&fx.top.params, &server.top_share, &encoded).to_bytes_be()
            }
            CMD_TOKEN => {
                let mut input = &frame[1..];
                let encoded = BigUint::from_bytes_be(take_bytes(&mut input)?);
                let payload = take_bytes(&mut input)?;
                if !input.is_empty() {
                    return Err("trailing token request data".into());
                }
                let message = signed_message(payload, &fx.client_id);
                let modulus_bytes = ((fx.ttg.public.n.bits() + 7) / 8) as usize;
                let representative = emsa_pkcs1_v1_5_sha256(&message, modulus_bytes)?;
                let z_i = toprf_eval(&fx.top.params, &server.top_share, &encoded);
                let partial = shoup_part_eval(&fx.ttg.public, &server.ttg_share, &representative);
                let mut encrypted_partial = partial.value.to_bytes_be();
                if encrypted_partial.len() < modulus_bytes {
                    let mut padded = vec![0u8; modulus_bytes - encrypted_partial.len()];
                    padded.extend_from_slice(&encrypted_partial);
                    encrypted_partial = padded;
                }
                let mut iv = [0u8; 16];
                rng.fill_bytes(&mut iv);
                aes128_ofb_apply(&server.h_i, &iv, &mut encrypted_partial);
                encode_response(&protocol::TokenResponse {
                    id: id as u32,
                    z_i,
                    encrypted_partial,
                    iv,
                })
            }
            CMD_UPDATE => {
                let mut input = &frame[1..];
                let signature = BigUint::from_bytes_be(take_bytes(&mut input)?);
                let body = take_bytes(&mut input)?;
                if !input.is_empty() {
                    return Err("trailing update data".into());
                }
                let message = signed_message(body, &fx.client_id);
                let representative =
                    emsa_pkcs1_v1_5_sha256(&message, ((fx.ttg.public.n.bits() + 7) / 8) as usize)?;
                let mut ok = shoup_verify(&fx.ttg.public, &representative, &signature);
                let chunk_len = 80;
                if ok && body.len() == n * chunk_len {
                    let off = (id - 1) * chunk_len;
                    let mut iv = [0u8; 16];
                    iv.copy_from_slice(&body[off..off + 16]);
                    let mut plaintext = body[off + 16..off + 80].to_vec();
                    aes128_ofb_apply(&server.h_i, &iv, &mut plaintext);
                    ok = plaintext[..32] == server.h_i;
                    if ok {
                        server.h_i.copy_from_slice(&plaintext[32..64]);
                    }
                } else {
                    ok = false;
                }
                vec![u8::from(ok)]
            }
            CMD_RESET => {
                server = template.clone();
                vec![1]
            }
            CMD_SHUTDOWN => {
                write_frame(&mut stream, &[1])?;
                break;
            }
            _ => return Err("unknown command".into()),
        };
        write_frame(&mut stream, &reply)?;
    }
    Ok(())
}

fn free_port() -> io::Result<u16> {
    Ok(TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port())
}

fn connect_retry(port: u16) -> io::Result<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error),
        }
    }
}

struct PaperTcpBench {
    fx: protocol::Fixture,
    streams: Vec<TcpStream>,
    children: Vec<Child>,
    rng: ChaCha20Rng,
}

impl PaperTcpBench {
    fn start(n: usize, t: usize, setup_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let setup = load_or_create_setup(setup_path, n, t)?;
        let fx = fixture(n, t, setup)?;
        let exe = env::current_exe()?;
        let mut children = Vec::with_capacity(n);
        let mut streams = Vec::with_capacity(n);
        for id in 1..=n {
            let port = free_port()?;
            let child = Command::new(&exe)
                .args([
                    "--server",
                    "--n",
                    &n.to_string(),
                    "--t",
                    &t.to_string(),
                    "--id",
                    &id.to_string(),
                    "--port",
                    &port.to_string(),
                    "--setup-file",
                    &setup_path.to_string_lossy(),
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?;
            children.push(child);
            streams.push(connect_retry(port)?);
        }
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(n as u64).to_le_bytes());
        seed[8..16].copy_from_slice(&(t as u64).to_le_bytes());
        seed[16..24].copy_from_slice(b"paper!!!");
        Ok(Self {
            fx,
            streams,
            children,
            rng: ChaCha20Rng::from_seed(seed),
        })
    }

    fn toprf_round(&mut self, password: &[u8], count: usize) -> io::Result<[u8; 32]> {
        let (encoded, rho) = toprf_encode(&self.fx.top.params, password, &mut self.rng);
        let mut request = vec![CMD_TOPRF];
        request.extend_from_slice(&encoded.to_bytes_be());
        let replies = parallel_exchange(&self.streams[..count], vec![request; count])?;
        let ids: Vec<u32> = (1..=count as u32).collect();
        let partials: Vec<BigUint> = replies.iter().map(|r| BigUint::from_bytes_be(r)).collect();
        toprf_combine(&self.fx.top.params, password, &rho, &ids, &partials)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn token(&mut self, password: &[u8], payload: &[u8], count: usize) -> io::Result<BigUint> {
        let (encoded, rho) = toprf_encode(&self.fx.top.params, password, &mut self.rng);
        let mut request = vec![CMD_TOKEN];
        put_bytes(&mut request, &encoded.to_bytes_be());
        put_bytes(&mut request, payload);
        let replies = parallel_exchange(&self.streams[..count], vec![request; count])?;
        let responses: Vec<_> = replies
            .iter()
            .map(|r| decode_response(r))
            .collect::<io::Result<_>>()?;
        let ids: Vec<u32> = responses.iter().map(|r| r.id).collect();
        let partials_toprf: Vec<_> = responses.iter().map(|r| r.z_i.clone()).collect();
        let h = toprf_combine(&self.fx.top.params, password, &rho, &ids, &partials_toprf)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let modulus_bytes = ((self.fx.ttg.public.n.bits() + 7) / 8) as usize;
        let message = signed_message(payload, &self.fx.client_id);
        let representative =
            emsa_pkcs1_v1_5_sha256(&message, modulus_bytes).map_err(|e| io::Error::other(e.to_string()))?;
        let mut partials = Vec::with_capacity(count);
        for response in responses {
            let mut bytes = response.encrypted_partial;
            let h_i = derive_hi(&h, response.id);
            aes128_ofb_apply(&h_i, &response.iv, &mut bytes);
            partials.push(ShoupPartial {
                id: response.id,
                value: BigUint::from_bytes_be(&bytes),
            });
        }
        shoup_combine(&self.fx.ttg.public, &representative, &partials)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn verify(&self, payload: &[u8], signature: &BigUint) -> io::Result<bool> {
        protocol::verify_token(&self.fx, payload, signature).map_err(|e| io::Error::other(e.to_string()))
    }

    fn password_update(&mut self) -> io::Result<()> {
        let old_password = self.fx.password.clone();
        let new_password = self.fx.new_password.clone();
        let old_h = self.toprf_round(&old_password, self.fx.t)?;
        let new_h = self.toprf_round(&new_password, self.fx.t)?;
        let mut body = Vec::with_capacity(self.fx.n * 80);
        for id in 1..=self.fx.n as u32 {
            let old = derive_hi(&old_h, id);
            let new = derive_hi(&new_h, id);
            let mut plaintext = Vec::with_capacity(64);
            plaintext.extend_from_slice(&old);
            plaintext.extend_from_slice(&new);
            let mut iv = [0u8; 16];
            self.rng.fill_bytes(&mut iv);
            aes128_ofb_apply(&old, &iv, &mut plaintext);
            body.extend_from_slice(&iv);
            body.extend_from_slice(&plaintext);
        }
        let signature = self.token(&old_password, &body, self.fx.t)?;
        if !self.verify(&body, &signature)? {
            return Err(io::Error::other("update token verification failed"));
        }
        let requests = (0..self.fx.n)
            .map(|_| {
                let mut request = vec![CMD_UPDATE];
                put_bytes(&mut request, &signature.to_bytes_be());
                put_bytes(&mut request, &body);
                request
            })
            .collect();
        let acks = parallel_exchange(&self.streams, requests)?;
        if acks.iter().any(|ack| ack.as_slice() != [1]) {
            return Err(io::Error::other("provider rejected update"));
        }
        Ok(())
    }

    fn reset(&self) -> io::Result<()> {
        let acks = parallel_exchange(&self.streams, (0..self.fx.n).map(|_| vec![CMD_RESET]).collect())?;
        if acks.iter().any(|ack| ack.as_slice() != [1]) {
            return Err(io::Error::other("provider reset failed"));
        }
        Ok(())
    }

    fn correctness(&mut self) -> io::Result<()> {
        let payload = self.fx.payload.clone();
        let password = self.fx.password.clone();
        let signature = self.token(&password, &payload, self.fx.t)?;
        if !self.verify(&payload, &signature)? {
            return Err(io::Error::other("valid token rejected"));
        }
        let mut changed = payload.clone();
        changed[0] ^= 1;
        if self.verify(&changed, &signature)? {
            return Err(io::Error::other("changed message accepted"));
        }
        let wrong = self.token(b"wrong password", &payload, self.fx.t)?;
        if self.verify(&payload, &wrong)? {
            return Err(io::Error::other("wrong password accepted"));
        }
        if self.fx.t > 1 {
            let fewer = self.token(&password, &payload, self.fx.t - 1)?;
            if self.verify(&payload, &fewer)? {
                return Err(io::Error::other("fewer than t shares accepted"));
            }
        }
        self.password_update()?;
        let old = self.token(&password, &payload, self.fx.t)?;
        if self.verify(&payload, &old)? {
            return Err(io::Error::other("old password accepted after update"));
        }
        let new_password = self.fx.new_password.clone();
        let new = self.token(&new_password, &payload, self.fx.t)?;
        if !self.verify(&payload, &new)? {
            return Err(io::Error::other("new password rejected after update"));
        }
        self.reset()
    }
}

impl Drop for PaperTcpBench {
    fn drop(&mut self) {
        for stream in &self.streams {
            let _ = exchange(stream, vec![CMD_SHUTDOWN]);
        }
        for child in &mut self.children {
            let _ = child.wait();
        }
    }
}

fn write_row(
    out: &mut dyn Write,
    metric: &str,
    network: &str,
    n: usize,
    t: usize,
    warmup: usize,
    s: &Stats,
) -> io::Result<()> {
    writeln!(
        out,
        "paper_style exp2 {metric} {network} {n} {t} {} {warmup} {} {} {} {} {:.3} {:.3}",
        s.n, s.min, s.p50, s.p95, s.max, s.mean, s.stddev
    )
}

fn benchmark_main(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let n = arg_usize(args, "--n", 3);
    let t = arg_usize(args, "--t", 2);
    let warmup = arg_usize(args, "--warmup", 100);
    let samples = arg_usize(args, "--samples", 100);
    let network = arg(args, "--network").unwrap_or_else(|| "lan4".to_string());
    let setup_path = PathBuf::from(arg(args, "--setup-file").ok_or("--setup-file is required")?);
    let out_path = PathBuf::from(arg(args, "--out").ok_or("--out is required")?);
    if t == 0 || t > n || samples == 0 {
        return Err("invalid n/t/samples".into());
    }
    let mut bench = PaperTcpBench::start(n, t, &setup_path)?;
    bench.correctness()?;
    let password = bench.fx.password.clone();
    let payload = bench.fx.payload.clone();
    for _ in 0..warmup {
        let _ = bench.token(&password, &payload, t)?;
    }
    let mut token_ns = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        let _ = bench.token(&password, &payload, t)?;
        token_ns.push(start.elapsed().as_nanos());
    }
    for _ in 0..warmup {
        bench.password_update()?;
        bench.reset()?;
    }
    let mut update_ns = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        bench.password_update()?;
        update_ns.push(start.elapsed().as_nanos());
        bench.reset()?;
    }
    let mut out = BufWriter::new(File::create(out_path)?);
    writeln!(
        out,
        "profile experiment metric network n t samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns"
    )?;
    write_row(
        &mut out,
        "token_generation_tcp",
        &network,
        n,
        t,
        warmup,
        &stats(token_ns),
    )?;
    write_row(
        &mut out,
        "password_update_tcp",
        &network,
        n,
        t,
        warmup,
        &stats(update_ns),
    )?;
    out.flush()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--server") {
        server_main(&args)
    } else {
        benchmark_main(&args)
    }
}
