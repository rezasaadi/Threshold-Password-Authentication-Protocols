#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bash "$ROOT/experiments/run_exp1.sh"
bash "$ROOT/experiments/run_exp2.sh"
bash "$ROOT/experiments/run_exp3.sh"
python3 "$ROOT/experiments/process_results.py" --root "$ROOT"
