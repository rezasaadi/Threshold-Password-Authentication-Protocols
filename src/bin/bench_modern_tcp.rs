use std::{
    env,
    fs::File,
    io::{self, BufWriter, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use curve25519_dalek::ristretto::CompressedRistretto;
use pastau_bench::{
    crypto_core, crypto_pastau as pc,
    protocols::pastau::{self, ClientState, ServerResponse},
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const CMD_TOPRF: u8 = 1;
const CMD_TOKEN: u8 = 2;
const CMD_TOKEN_VAR: u8 = 3;
const CMD_UPDATE: u8 = 4;
const CMD_RESET: u8 = 5;
const CMD_SHUTDOWN: u8 = 6;

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

fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()
}

fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    let mut bytes = vec![0u8; len];
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

fn encode_response(resp: &ServerResponse) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + pc::NONCE_LEN + pc::TTG_TOKEN_LEN + pc::TAG_LEN);
    out.extend_from_slice(&resp.server_id.to_be_bytes());
    out.extend_from_slice(&resp.z_i);
    out.extend_from_slice(&resp.ctxt_i.nonce);
    out.extend_from_slice(&resp.ctxt_i.ct);
    out.extend_from_slice(&resp.ctxt_i.tag);
    out
}

fn decode_response(bytes: &[u8]) -> io::Result<ServerResponse> {
    let expected = 4 + 32 + pc::NONCE_LEN + pc::TTG_TOKEN_LEN + pc::TAG_LEN;
    if bytes.len() != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad token response length",
        ));
    }
    let mut off = 0;
    let server_id = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap());
    off += 4;
    let mut z_i = [0u8; 32];
    z_i.copy_from_slice(&bytes[off..off + 32]);
    off += 32;
    let mut nonce = [0u8; pc::NONCE_LEN];
    nonce.copy_from_slice(&bytes[off..off + pc::NONCE_LEN]);
    off += pc::NONCE_LEN;
    let mut ct = [0u8; pc::TTG_TOKEN_LEN];
    ct.copy_from_slice(&bytes[off..off + pc::TTG_TOKEN_LEN]);
    off += pc::TTG_TOKEN_LEN;
    let mut tag = [0u8; pc::TAG_LEN];
    tag.copy_from_slice(&bytes[off..off + pc::TAG_LEN]);
    Ok(ServerResponse {
        server_id,
        z_i,
        ctxt_i: pc::CtBlob { nonce, ct, tag },
    })
}

fn server_main(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let n = arg_usize(args, "--n", 3);
    let t = arg_usize(args, "--t", 2);
    let id = arg_usize(args, "--id", 1);
    let port = arg_usize(args, "--port", 0);
    let fx = pastau::make_fixture(n, t);
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
                if frame.len() != 33 {
                    return Err("bad TOPRF request".into());
                }
                let req: [u8; 32] = frame[1..].try_into().unwrap();
                pastau::respond_toprf_only(&server, fx.c, &req)
                    .ok_or("TOPRF response failed")?
                    .to_vec()
            }
            CMD_TOKEN => {
                if frame.len() != 65 {
                    return Err("bad token request".into());
                }
                let req: [u8; 32] = frame[1..33].try_into().unwrap();
                let x: [u8; 32] = frame[33..65].try_into().unwrap();
                encode_response(
                    &pastau::respond(&server, fx.c, x, &req, &mut rng).ok_or("token response failed")?,
                )
            }
            CMD_TOKEN_VAR => {
                if frame.len() < 33 {
                    return Err("bad variable token request".into());
                }
                let req: [u8; 32] = frame[1..33].try_into().unwrap();
                encode_response(
                    &pastau::respond_var_payload(&server, fx.c, &frame[33..], &req, &mut rng)
                        .ok_or("variable token response failed")?,
                )
            }
            CMD_UPDATE => {
                if frame.len() < 1 + pc::TTG_TOKEN_LEN {
                    return Err("bad update request".into());
                }
                let token: pc::TtgToken = frame[1..1 + pc::TTG_TOKEN_LEN].try_into().unwrap();
                vec![u8::from(pastau::password_update_handle(
                    &mut server,
                    &fx.vk,
                    &frame[1 + pc::TTG_TOKEN_LEN..],
                    &token,
                ))]
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

struct ModernTcpBench {
    fx: pastau::Fixture,
    streams: Vec<TcpStream>,
    children: Vec<Child>,
    rng: ChaCha20Rng,
}

impl ModernTcpBench {
    fn start(n: usize, t: usize) -> Result<Self, Box<dyn std::error::Error>> {
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
        seed[16..24].copy_from_slice(b"modern!!");
        Ok(Self {
            fx: pastau::make_fixture(n, t),
            streams,
            children,
            rng: ChaCha20Rng::from_seed(seed),
        })
    }

    fn responses(&self, command: u8, req: &[u8; 32], payload: &[u8]) -> io::Result<Vec<ServerResponse>> {
        let requests = (0..self.fx.t)
            .map(|_| {
                let mut frame = Vec::with_capacity(33 + payload.len());
                frame.push(command);
                frame.extend_from_slice(req);
                frame.extend_from_slice(payload);
                frame
            })
            .collect();
        parallel_exchange(&self.streams[..self.fx.t], requests)?
            .iter()
            .map(|bytes| decode_response(bytes))
            .collect()
    }

    fn token_fixed(&mut self, password: &[u8]) -> io::Result<Option<pc::TtgToken>> {
        let (st, req) = pastau::request(self.fx.c, password, self.fx.x, &self.fx.t_set, &mut self.rng);
        let responses = self.responses(CMD_TOKEN, &req.req, &req.x)?;
        Ok(pastau::finalize(&st, &responses))
    }

    fn token_var(&mut self, password: &[u8], payload: &[u8]) -> io::Result<Option<pc::TtgToken>> {
        let rho = crypto_core::random_scalar(&mut self.rng);
        let req = pc::toprf_encode(password, rho).compress().to_bytes();
        let responses = self.responses(CMD_TOKEN_VAR, &req, payload)?;
        let st = ClientState {
            c: self.fx.c,
            password: password.to_vec(),
            rho,
            t_set: self.fx.t_set.clone(),
        };
        Ok(pastau::finalize(&st, &responses))
    }

    fn toprf_round(&mut self, password: &[u8]) -> io::Result<[u8; 32]> {
        let rho = crypto_core::random_scalar(&mut self.rng);
        let req = pc::toprf_encode(password, rho).compress().to_bytes();
        let requests = (0..self.fx.t)
            .map(|_| {
                let mut frame = Vec::with_capacity(33);
                frame.push(CMD_TOPRF);
                frame.extend_from_slice(&req);
                frame
            })
            .collect();
        let replies = parallel_exchange(&self.streams[..self.fx.t], requests)?;
        let mut partials = Vec::with_capacity(self.fx.t);
        for reply in replies {
            let bytes: [u8; 32] = reply
                .as_slice()
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad TOPRF reply"))?;
            partials.push(
                CompressedRistretto(bytes)
                    .decompress()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid TOPRF point"))?,
            );
        }
        let lambdas = crypto_core::lagrange_coeffs_at_zero(&self.fx.t_set);
        Ok(crypto_core::toprf_client_eval_from_partials(
            password, rho, &partials, &lambdas,
        ))
    }

    fn password_update(&mut self) -> io::Result<()> {
        let old_password = self.fx.password.clone();
        let new_password = b"new correct horse battery staple".to_vec();
        let old_h = self.toprf_round(&old_password)?;
        let new_h = self.toprf_round(&new_password)?;
        let old_hi: Vec<_> = (1..=self.fx.n as u32).map(|id| pc::hash_hi(&old_h, id)).collect();
        let new_hi: Vec<_> = (1..=self.fx.n as u32).map(|id| pc::hash_hi(&new_h, id)).collect();
        let mut body = Vec::with_capacity(self.fx.n * pastau::UPDATE_BLOB_LEN);
        for i in 0..self.fx.n {
            let mut plaintext = [0u8; pastau::UPDATE_PT_LEN];
            plaintext[..32].copy_from_slice(&old_hi[i]);
            plaintext[32..].copy_from_slice(&new_hi[i]);
            let blob = pc::xchacha_encrypt_detached(&old_hi[i], &[], &plaintext, &mut self.rng);
            body.extend_from_slice(&blob.nonce);
            body.extend_from_slice(&blob.ct);
            body.extend_from_slice(&blob.tag);
        }
        let token = self
            .token_var(&old_password, &body)?
            .ok_or_else(|| io::Error::other("update token generation failed"))?;
        let mut pld3 = body;
        pld3.extend_from_slice(&self.fx.c.0);
        if !pc::ttg_verify(&self.fx.vk, &pld3, &token) {
            return Err(io::Error::other("update token verification failed"));
        }
        let requests = (0..self.fx.n)
            .map(|_| {
                let mut frame = Vec::with_capacity(1 + token.len() + pld3.len());
                frame.push(CMD_UPDATE);
                frame.extend_from_slice(&token);
                frame.extend_from_slice(&pld3);
                frame
            })
            .collect();
        let acks = parallel_exchange(&self.streams, requests)?;
        if acks.iter().any(|ack| ack.as_slice() != [1]) {
            return Err(io::Error::other("provider rejected password update"));
        }
        Ok(())
    }

    fn reset(&self) -> io::Result<()> {
        let requests = (0..self.fx.n).map(|_| vec![CMD_RESET]).collect();
        let acks = parallel_exchange(&self.streams, requests)?;
        if acks.iter().any(|ack| ack.as_slice() != [1]) {
            return Err(io::Error::other("provider reset failed"));
        }
        Ok(())
    }

    fn correctness(&mut self) -> io::Result<()> {
        let password = self.fx.password.clone();
        let token = self
            .token_fixed(&password)?
            .ok_or_else(|| io::Error::other("correct-password token failed"))?;
        if !pastau::verify(&self.fx.vk, self.fx.c, self.fx.x, &token) {
            return Err(io::Error::other("valid token rejected"));
        }
        let mut changed = self.fx.x;
        changed[0] ^= 1;
        if pastau::verify(&self.fx.vk, self.fx.c, changed, &token) {
            return Err(io::Error::other("changed message accepted"));
        }
        let wrong = self.token_fixed(b"wrong password")?;
        if wrong
            .as_ref()
            .is_some_and(|tk| pastau::verify(&self.fx.vk, self.fx.c, self.fx.x, tk))
        {
            return Err(io::Error::other("wrong password accepted"));
        }

        if self.fx.t > 1 {
            let rho = crypto_core::random_scalar(&mut self.rng);
            let req = pc::toprf_encode(&password, rho).compress().to_bytes();
            let requests = (0..self.fx.t - 1)
                .map(|_| {
                    let mut frame = vec![CMD_TOKEN];
                    frame.extend_from_slice(&req);
                    frame.extend_from_slice(&self.fx.x);
                    frame
                })
                .collect();
            let responses: Vec<_> = parallel_exchange(&self.streams[..self.fx.t - 1], requests)?
                .iter()
                .map(|r| decode_response(r))
                .collect::<io::Result<_>>()?;
            let st = ClientState {
                c: self.fx.c,
                password: password.clone(),
                rho,
                t_set: (1..self.fx.t as u32).collect(),
            };
            if pastau::finalize(&st, &responses)
                .as_ref()
                .is_some_and(|tk| pastau::verify(&self.fx.vk, self.fx.c, self.fx.x, tk))
            {
                return Err(io::Error::other("fewer than t shares accepted"));
            }
        }

        self.password_update()?;
        let old = self.token_fixed(&password)?;
        if old
            .as_ref()
            .is_some_and(|tk| pastau::verify(&self.fx.vk, self.fx.c, self.fx.x, tk))
        {
            return Err(io::Error::other("old password accepted after update"));
        }
        let new_password = b"new correct horse battery staple";
        let new_token = self
            .token_fixed(new_password)?
            .ok_or_else(|| io::Error::other("new password failed after update"))?;
        if !pastau::verify(&self.fx.vk, self.fx.c, self.fx.x, &new_token) {
            return Err(io::Error::other("new-password token rejected"));
        }
        self.reset()
    }
}

impl Drop for ModernTcpBench {
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
        "modern exp2 {metric} {network} {n} {t} {} {warmup} {} {} {} {} {:.3} {:.3}",
        s.n, s.min, s.p50, s.p95, s.max, s.mean, s.stddev
    )
}

fn benchmark_main(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let n = arg_usize(args, "--n", 3);
    let t = arg_usize(args, "--t", 2);
    let warmup = arg_usize(args, "--warmup", 100);
    let samples = arg_usize(args, "--samples", 100);
    let network = arg(args, "--network").unwrap_or_else(|| "lan4".to_string());
    let out_path = PathBuf::from(arg(args, "--out").ok_or("--out is required")?);
    if t == 0 || t > n || samples == 0 {
        return Err("invalid n/t/samples".into());
    }

    let mut bench = ModernTcpBench::start(n, t)?;
    bench.correctness()?;
    let password = bench.fx.password.clone();
    for _ in 0..warmup {
        let _ = bench.token_fixed(&password)?.ok_or("warmup token failed")?;
    }
    let mut token_ns = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        let _ = bench.token_fixed(&password)?.ok_or("timed token failed")?;
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
