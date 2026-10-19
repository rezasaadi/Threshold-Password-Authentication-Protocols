#!/usr/bin/env bash
set -euo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
exec bash "$ROOT/scripts/run_all_paper_raw.sh" "$@"
