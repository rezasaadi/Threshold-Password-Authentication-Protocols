#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RAW="$ROOT/results/raw"
mkdir -p "$RAW"
PAIRS=("3 2" "6 3" "10 5" "10 10")

for run in 1 2 3; do
  for pair in "${PAIRS[@]}"; do
    read -r n t <<<"$pair"
    cargo run --release --manifest-path "$ROOT/Cargo.toml" --bin bench_modern -- \
      --kind prim,proto \
      --nsp "$n" --tsp "$t" \
      --sample-size 100 --warmup-iters 100 \
      --out "$RAW/exp1_modern_${n}_${t}_run${run}.dat"

    cargo run --release --manifest-path "$ROOT/pastau_paper/Cargo.toml" --bin bench_paper -- \
      --n "$n" --t "$t" --samples 100 --warmup 100 \
      --setup-file "$ROOT/pastau_paper/setup_${n}_${t}.json" \
      --out "$RAW/exp1_paper_style_${n}_${t}_run${run}.dat"
  done
done
