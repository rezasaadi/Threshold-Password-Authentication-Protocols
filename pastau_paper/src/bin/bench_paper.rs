use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::PathBuf,
    time::Instant,
};

use num_bigint::BigUint;
use pastau_paper::{paper_crypto::*, protocol::*};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[derive(Debug)]
struct Stats {
    n: usize,
    min_ns: u128,
    p50_ns: u128,
    p95_ns: u128,
    max_ns: u128,
    mean_ns: f64,
    stddev_ns: f64,
}

fn stats(mut xs: Vec<u128>) -> Stats {
    assert!(!xs.is_empty());
    xs.sort_unstable();
    let n = xs.len();
    let mean_ns = xs.iter().map(|x| *x as f64).sum::<f64>() / n as f64;
    let stddev_ns = if n > 1 {
        let var = xs
            .iter()
            .map(|x| {
                let d = *x as f64 - mean_ns;
                d * d
            })
            .sum::<f64>()
            / (n - 1) as f64;
        var.sqrt()
    } else {
        0.0
    };
    Stats {
        n,
        min_ns: xs[0],
        p50_ns: xs[n / 2],
        p95_ns: xs[(n * 95) / 100],
        max_ns: xs[n - 1],
        mean_ns,
        stddev_ns,
    }
}

fn bench(mut f: impl FnMut(), warmup: usize, samples: usize) -> Stats {
    for _ in 0..warmup {
        f();
    }
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        f();
        xs.push(start.elapsed().as_nanos());
    }
    stats(xs)
}

fn parse_usize(args: &[String], name: &str, default: usize) -> usize {
    args.windows(2)
        .find(|w| w[0] == name)
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(default)
}

fn parse_path(args: &[String], name: &str) -> Option<PathBuf> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| PathBuf::from(&w[1]))
}

fn write_row(
    out: &mut dyn Write,
    metric: &str,
    n: usize,
    t: usize,
    warmup: usize,
    s: &Stats,
) -> std::io::Result<()> {
    writeln!(
        out,
        "paper_style exp1 {} {} {} {} {} {} {} {} {} {:.3} {:.3}",
        metric, n, t, s.n, warmup, s.min_ns, s.p50_ns, s.p95_ns, s.max_ns, s.mean_ns, s.stddev_ns
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let n = parse_usize(&args, "--n", 3);
    let t = parse_usize(&args, "--t", 2);
    let samples = parse_usize(&args, "--samples", 100);
    let warmup = parse_usize(&args, "--warmup", 100);
    let setup_path = parse_path(&args, "--setup-file")
        .unwrap_or_else(|| PathBuf::from(format!("paper_shoup_{}_{}.json", n, t)));
    let out_path = parse_path(&args, "--out");

    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let setup: ShoupSetup = if setup_path.exists() {
        serde_json::from_slice(&fs::read(&setup_path)?)?
    } else {
        eprintln!("Generating one cached 2048-bit Shoup threshold-RSA setup...");
        let setup = shoup_setup(n, t, &mut rng)?;
        fs::write(&setup_path, serde_json::to_vec(&setup)?)?;
        setup
    };

    let fx = setup_fixture_with_ttg(n, t, setup, &mut rng)?;
    let sig = token_generation(&fx, &fx.payload, &fx.password, &mut rng)?;
    assert!(verify_token(&fx, &fx.payload, &sig)?);

    let mut msg = fx.payload.clone();
    msg.extend_from_slice(&fx.client_id);
    let em = emsa_pkcs1_v1_5_sha256(&msg, ((fx.ttg.public.n.bits() + 7) / 8) as usize)?;
    let share = fx.ttg.shares[0].clone();
    let ids: Vec<u32> = (1..=t as u32).collect();
    let partials: Vec<_> = ids
        .iter()
        .map(|&id| shoup_part_eval(&fx.ttg.public, &fx.ttg.shares[(id - 1) as usize], &em))
        .collect();

    let part = bench(
        || {
            let p = shoup_part_eval(&fx.ttg.public, &share, &em);
            std::hint::black_box(p);
        },
        warmup,
        samples,
    );

    let mut combined = BigUint::default();
    let combine = bench(
        || {
            combined = shoup_combine(&fx.ttg.public, &em, &partials).expect("combine");
            std::hint::black_box(&combined);
        },
        warmup,
        samples,
    );

    let verify = bench(
        || {
            assert!(shoup_verify(&fx.ttg.public, &em, &combined));
        },
        warmup,
        samples,
    );

    let mut rng_token = ChaCha20Rng::from_seed([9u8; 32]);
    let token = bench(
        || {
            let z =
                token_generation(&fx, &fx.payload, &fx.password, &mut rng_token).expect("token generation");
            std::hint::black_box(z);
        },
        warmup,
        samples,
    );

    let mut rng_update = ChaCha20Rng::from_seed([11u8; 32]);
    let update = bench(
        || {
            let mut local = fx.clone();
            let z = password_update(&mut local, &mut rng_update).expect("password update");
            assert_eq!(z.updated, n);
        },
        warmup,
        samples,
    );

    let mut writer: Box<dyn Write> = match out_path {
        Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        None => Box::new(std::io::stdout()),
    };
    writeln!(
        writer,
        "profile experiment metric n t samples warmup min_ns p50_ns p95_ns max_ns mean_ns stddev_ns"
    )?;
    write_row(&mut writer, "ttg_part_eval", n, t, warmup, &part)?;
    write_row(&mut writer, "ttg_combine_t", n, t, warmup, &combine)?;
    write_row(&mut writer, "ttg_verify", n, t, warmup, &verify)?;
    write_row(&mut writer, "token_generation_cpu", n, t, warmup, &token)?;
    write_row(&mut writer, "password_update_cpu", n, t, warmup, &update)?;
    writer.flush()?;
    Ok(())
}
