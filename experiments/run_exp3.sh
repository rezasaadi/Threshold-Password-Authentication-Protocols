#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RAW="$ROOT/results/raw"
mkdir -p "$RAW"
SSH_TARGET="${SSH_TARGET:-localhost}"
SSH_PORT="${SSH_PORT:-22222}"
SSH_USER="${SSH_USER:-$(id -un)}"
SSH_AUTHORIZED_KEYS="${SSH_AUTHORIZED_KEYS:-$ROOT/experiments/ssh_test/authorized_keys}"
SSH_KNOWN_HOSTS="${SSH_KNOWN_HOSTS:-$ROOT/experiments/ssh_test/known_hosts}"
PAIRS=("3 2" "6 3" "10 5" "10 10")

cargo build --release --manifest-path "$ROOT/pastau_paper/Cargo.toml" --bin pastau_ssh_agent

cleanup() {
  sudo tc qdisc del dev lo root 2>/dev/null || true
  [ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null || true
}
trap cleanup EXIT

for profile in lan4 wan80; do
  if [ "$profile" = lan4 ]; then delay=2ms; else delay=40ms; fi
  sudo tc qdisc replace dev lo root netem delay "$delay"
  for run in 1 2 3; do
    for pair in "${PAIRS[@]}"; do
      read -r n t <<<"$pair"
      sock="/tmp/pastau-agent-${n}-${t}-${run}.sock"
      log="$RAW/exp3_ssh_${profile}_${n}_${t}_run${run}.dat"
      handshake_samples="${log}.handshake_ns"
      if [ -f "$log" ] && [ "$(wc -l < "$log")" -eq 3 ]; then
        continue
      fi
      rm -f "$sock"
      rm -f "$log" "$handshake_samples"
      "$ROOT/pastau_paper/target/release/pastau_ssh_agent" \
        --n "$n" --t "$t" \
        --setup-file "$ROOT/pastau_paper/setup_${n}_${t}.json" \
        --socket "$sock" --out "$log" \
        --network "$profile" --warmup 100 --samples 100 &
      AGENT_PID=$!
      for _ in $(seq 1 100); do
        [ -S "$sock" ] && break
        sleep 0.05
      done
      [ -S "$sock" ] || { echo "agent socket was not created" >&2; exit 1; }
      SSH_AUTH_SOCK="$sock" ssh-add -L > "$RAW/exp3_public_key_${n}_${t}.txt"
      mkdir -p "$(dirname "$SSH_AUTHORIZED_KEYS")"
      touch "$SSH_AUTHORIZED_KEYS"
      key_line="$(cat "$RAW/exp3_public_key_${n}_${t}.txt")"
      grep -qxF "$key_line" "$SSH_AUTHORIZED_KEYS" || printf '%s\n' "$key_line" >> "$SSH_AUTHORIZED_KEYS"

      SSH_AUTH_SOCK="$sock" python3 - \
        "$handshake_samples" "$SSH_PORT" "$SSH_USER@$SSH_TARGET" "$sock" "$SSH_KNOWN_HOSTS" <<'PY'
import os
import subprocess
import sys
import time

output, port, target, socket_path, known_hosts = sys.argv[1:]
command = [
    "ssh", "-p", port,
    "-o", "BatchMode=yes",
    "-o", f"IdentityAgent={socket_path}",
    "-o", "PubkeyAcceptedAlgorithms=rsa-sha2-256",
    "-o", "StrictHostKeyChecking=no",
    "-o", f"UserKnownHostsFile={known_hosts}",
    "-o", "LogLevel=ERROR",
    target, "true",
]
environment = os.environ.copy()
environment["SSH_AUTH_SOCK"] = socket_path
for _ in range(100):
    subprocess.run(command, check=True, env=environment)
with open(output, "w", encoding="ascii") as stream:
    for _ in range(100):
        started = time.perf_counter_ns()
        subprocess.run(command, check=True, env=environment)
        stream.write(f"{time.perf_counter_ns() - started}\n")
PY
      kill "$AGENT_PID"
      wait "$AGENT_PID" 2>/dev/null || true
      unset AGENT_PID
      "$ROOT/pastau_paper/target/release/pastau_ssh_agent" \
        --append-handshakes "$handshake_samples" --out "$log" \
        --n "$n" --t "$t" --network "$profile" --warmup 100 --samples 100
    done
  done
done
