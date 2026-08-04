#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RAW="$ROOT/results/raw"
mkdir -p "$RAW"
PAIRS=("3 2" "6 3" "10 5" "10 10")

for bin in bench_modern_tcp bench_paper_tcp; do
  cargo build --release --manifest-path "$ROOT/$([ "$bin" = bench_paper_tcp ] && echo pastau_paper/Cargo.toml || echo Cargo.toml)" --bin "$bin"
done

cleanup() { sudo tc qdisc del dev lo root 2>/dev/null || true; }
trap cleanup EXIT

for profile in lan4 wan80; do
  if [ "$profile" = lan4 ]; then delay=2ms; else delay=40ms; fi
  sudo tc qdisc replace dev lo root netem delay "$delay"
  for run in 1 2 3; do
    for pair in "${PAIRS[@]}"; do
      read -r n t <<<"$pair"
      cargo run --release --manifest-path "$ROOT/Cargo.toml" --bin bench_modern_tcp -- \
        --n "$n" --t "$t" --warmup 100 --samples 100 --network "$profile" \
        --out "$RAW/exp2_modern_${profile}_${n}_${t}_run${run}.dat"
      cargo run --release --manifest-path "$ROOT/pastau_paper/Cargo.toml" --bin bench_paper_tcp -- \
        --n "$n" --t "$t" --warmup 100 --samples 100 --network "$profile" \
        --setup-file "$ROOT/pastau_paper/setup_${n}_${t}.json" \
        --out "$RAW/exp2_paper_style_${profile}_${n}_${t}_run${run}.dat"
    done
  done
done
