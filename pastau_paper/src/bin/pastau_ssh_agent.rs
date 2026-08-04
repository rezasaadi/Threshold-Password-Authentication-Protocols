#[cfg(unix)]
mod unix_agent {
    use std::{
        env,
        fs::{self, File, OpenOptions},
        io::{self, BufRead, BufReader, Read, Write},
        os::unix::net::{UnixListener, UnixStream},
        path::{Path, PathBuf},
        time::Instant,
    };

    use num_bigint::BigUint;
    use pastau_paper::{paper_crypto::*, protocol};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    const SSH_AGENT_FAILURE: u8 = 5;
    const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
    const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
    const SSH_AGENT_RSA_SHA2_256: u32 = 2;

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

    fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    fn take_string<'a>(input: &mut &'a [u8]) -> io::Result<&'a [u8]> {
        if input.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "missing string length",
            ));
        }
        let len = u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;
        *input = &input[4..];
        if input.len() < len {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short string"));
        }
        let (value, rest) = input.split_at(len);
        *input = rest;
        Ok(value)
    }

    fn mpint(value: &BigUint) -> Vec<u8> {
        let mut bytes = value.to_bytes_be();
        if bytes.first().is_some_and(|b| b & 0x80 != 0) {
            bytes.insert(0, 0);
        }
        bytes
    }

    fn public_key_blob(setup: &ShoupSetup) -> Vec<u8> {
        let mut blob = Vec::new();
        put_string(&mut blob, b"ssh-rsa");
        put_string(&mut blob, &mpint(&setup.public.e));
        put_string(&mut blob, &mpint(&setup.public.n));
        blob
    }

    fn read_packet(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
        let mut len = [0u8; 4];
        match stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        }
        let mut payload = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut payload)?;
        Ok(Some(payload))
    }

    fn write_packet(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
        stream.write_all(&(payload.len() as u32).to_be_bytes())?;
        stream.write_all(payload)?;
        stream.flush()
    }

    fn load_setup(path: &Path) -> Result<ShoupSetup, Box<dyn std::error::Error>> {
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }

    fn make_fixture(n: usize, t: usize, setup: ShoupSetup) -> Result<protocol::Fixture, CryptoError> {
        let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
        protocol::setup_fixture_with_ttg(n, t, setup, &mut rng)
    }

    fn threshold_sign_exact(
        fx: &protocol::Fixture,
        data: &[u8],
        rng: &mut ChaCha20Rng,
    ) -> Result<BigUint, CryptoError> {
        let ids: Vec<u32> = (1..=fx.t as u32).collect();
        let (encoded, rho) = toprf_encode(&fx.top.params, &fx.password, rng);
        let modulus_bytes = ((fx.ttg.public.n.bits() + 7) / 8) as usize;
        let representative = emsa_pkcs1_v1_5_sha256(data, modulus_bytes)?;
        let mut responses = Vec::with_capacity(fx.t);
        for &id in &ids {
            let server = &fx.servers[(id - 1) as usize];
            let z_i = toprf_eval(&fx.top.params, &server.top_share, &encoded);
            let partial = shoup_part_eval(&fx.ttg.public, &server.ttg_share, &representative);
            let mut encrypted = partial.value.to_bytes_be();
            if encrypted.len() < modulus_bytes {
                let mut padded = vec![0u8; modulus_bytes - encrypted.len()];
                padded.extend_from_slice(&encrypted);
                encrypted = padded;
            }
            let mut iv = [0u8; 16];
            rng.fill_bytes(&mut iv);
            aes128_ofb_apply(&server.h_i, &iv, &mut encrypted);
            responses.push((id, z_i, encrypted, iv));
        }
        let z_values: Vec<_> = responses.iter().map(|(_, z, _, _)| z.clone()).collect();
        let h = toprf_combine(&fx.top.params, &fx.password, &rho, &ids, &z_values)?;
        let mut partials = Vec::with_capacity(fx.t);
        for (id, _, mut encrypted, iv) in responses {
            let h_i = derive_hi(&h, id);
            aes128_ofb_apply(&h_i, &iv, &mut encrypted);
            partials.push(ShoupPartial {
                id,
                value: BigUint::from_bytes_be(&encrypted),
            });
        }
        let signature = shoup_combine(&fx.ttg.public, &representative, &partials)?;
        if !shoup_verify(&fx.ttg.public, &representative, &signature) {
            return Err(CryptoError::InvalidRepresentative);
        }
        Ok(signature)
    }

    fn write_metric(
        path: &Path,
        append: bool,
        metric: &str,
        network: &str,
        n: usize,
        t: usize,
        warmup: usize,
        s: &Stats,
    ) -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.create(true).write(true);
        if append {
            options.append(true);
        } else {
            options.truncate(true);
        }
        let mut out = options.open(path)?;
        if !append {
            writeln!(
                out,
                "profile experiment metric network n t samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns"
            )?;
        }
        writeln!(
            out,
            "paper_style exp3 {metric} {network} {n} {t} {} {warmup} {} {} {} {} {:.3} {:.3}",
            s.n, s.min, s.p50, s.p95, s.max, s.mean, s.stddev
        )
    }

    fn append_handshakes(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        let n = arg_usize(args, "--n", 3);
        let t = arg_usize(args, "--t", 2);
        let warmup = arg_usize(args, "--warmup", 100);
        let samples = arg_usize(args, "--samples", 100);
        let network = arg(args, "--network").ok_or("--network is required")?;
        let input = PathBuf::from(arg(args, "--append-handshakes").ok_or("missing handshake file")?);
        let out = PathBuf::from(arg(args, "--out").ok_or("--out is required")?);
        let values: Vec<u128> = BufReader::new(File::open(input)?)
            .lines()
            .map(|line| Ok(line?.trim().parse::<u128>()?))
            .collect::<Result<_, Box<dyn std::error::Error>>>()?;
        if values.len() != samples {
            return Err(format!("expected {samples} handshake samples, found {}", values.len()).into());
        }
        write_metric(
            &out,
            true,
            "ssh_handshake",
            &network,
            n,
            t,
            warmup,
            &stats(values),
        )?;
        Ok(())
    }

    struct Agent {
        fx: protocol::Fixture,
        key_blob: Vec<u8>,
        rng: ChaCha20Rng,
        warmup: usize,
        samples: usize,
        sign_count: usize,
        durations: Vec<u128>,
        output: PathBuf,
        network: String,
    }

    impl Agent {
        fn handle(&mut self, packet: &[u8]) -> io::Result<Vec<u8>> {
            if packet.is_empty() {
                return Ok(vec![SSH_AGENT_FAILURE]);
            }
            match packet[0] {
                SSH_AGENTC_REQUEST_IDENTITIES => {
                    let mut answer = vec![SSH_AGENT_IDENTITIES_ANSWER];
                    answer.extend_from_slice(&1u32.to_be_bytes());
                    put_string(&mut answer, &self.key_blob);
                    put_string(&mut answer, b"PAS-TA-U Shoup RSA-2048");
                    Ok(answer)
                }
                SSH_AGENTC_SIGN_REQUEST => {
                    let mut input = &packet[1..];
                    let key = take_string(&mut input)?;
                    let data = take_string(&mut input)?;
                    if input.len() != 4 || key != self.key_blob {
                        return Ok(vec![SSH_AGENT_FAILURE]);
                    }
                    let flags = u32::from_be_bytes(input.try_into().unwrap());
                    if flags != SSH_AGENT_RSA_SHA2_256 {
                        return Ok(vec![SSH_AGENT_FAILURE]);
                    }
                    let started = Instant::now();
                    let signature = threshold_sign_exact(&self.fx, data, &mut self.rng)
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    let elapsed = started.elapsed().as_nanos();
                    self.sign_count += 1;
                    if self.sign_count > self.warmup && self.durations.len() < self.samples {
                        self.durations.push(elapsed);
                        if self.durations.len() == self.samples {
                            write_metric(
                                &self.output,
                                false,
                                "ssh_sign_service",
                                &self.network,
                                self.fx.n,
                                self.fx.t,
                                self.warmup,
                                &stats(self.durations.clone()),
                            )?;
                        }
                    }
                    let modulus_bytes = ((self.fx.ttg.public.n.bits() + 7) / 8) as usize;
                    let mut raw = signature.to_bytes_be();
                    if raw.len() < modulus_bytes {
                        let mut padded = vec![0u8; modulus_bytes - raw.len()];
                        padded.extend_from_slice(&raw);
                        raw = padded;
                    }
                    let mut signature_blob = Vec::new();
                    put_string(&mut signature_blob, b"rsa-sha2-256");
                    put_string(&mut signature_blob, &raw);
                    let mut answer = vec![SSH_AGENT_SIGN_RESPONSE];
                    put_string(&mut answer, &signature_blob);
                    Ok(answer)
                }
                _ => Ok(vec![SSH_AGENT_FAILURE]),
            }
        }
    }

    fn serve(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        let n = arg_usize(args, "--n", 3);
        let t = arg_usize(args, "--t", 2);
        let warmup = arg_usize(args, "--warmup", 100);
        let samples = arg_usize(args, "--samples", 100);
        let network = arg(args, "--network").ok_or("--network is required")?;
        let setup_path = PathBuf::from(arg(args, "--setup-file").ok_or("--setup-file is required")?);
        let socket_path = PathBuf::from(arg(args, "--socket").ok_or("--socket is required")?);
        let output = PathBuf::from(arg(args, "--out").ok_or("--out is required")?);
        if socket_path.exists() {
            fs::remove_file(&socket_path)?;
        }
        let setup = load_setup(&setup_path)?;
        let key_blob = public_key_blob(&setup);
        let fx = make_fixture(n, t, setup)?;
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(n as u64).to_le_bytes());
        seed[8..16].copy_from_slice(&(t as u64).to_le_bytes());
        seed[16..24].copy_from_slice(b"sshagent");
        let mut agent = Agent {
            fx,
            key_blob,
            rng: ChaCha20Rng::from_seed(seed),
            warmup,
            samples,
            sign_count: 0,
            durations: Vec::with_capacity(samples),
            output,
            network,
        };
        let listener = UnixListener::bind(&socket_path)?;
        for connection in listener.incoming() {
            let mut stream = connection?;
            while let Some(packet) = read_packet(&mut stream)? {
                let reply = agent.handle(&packet)?;
                write_packet(&mut stream, &reply)?;
            }
        }
        Ok(())
    }

    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<String> = env::args().collect();
        if args.iter().any(|a| a == "--append-handshakes") {
            append_handshakes(&args)
        } else {
            serve(&args)
        }
    }
}

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    unix_agent::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("pastau_ssh_agent requires Linux or WSL2");
    std::process::exit(1);
}
