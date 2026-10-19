#!/usr/bin/env python3
"""Rebuild, validate, run and retain the paper experiment evidence (runner v2)."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

from paper_configs import write_matrix
from summarize_raw import summarize_tree


def enabled(name, default=False):
    value = os.environ.get(name, '1' if default else '0')
    if value not in ('0', '1'):
        raise ValueError(f'{name} must be 0 or 1')
    return value == '1'


def save_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + '\n')


def build(root, output):
    if os.environ.get('NET_BIN'):
        raise ValueError('NET_BIN override is not supported: runner v2 uses only the binary produced by cargo for this source tree')
    if not shutil.which('cargo'):
        raise RuntimeError('cargo is missing from PATH; install the pinned Rust toolchain before running the suite')
    command = ['cargo', 'build', '--locked', '--release', '--bin', 'bench_network', '--message-format=json-render-diagnostics']
    print('Building bench_network from the current source (no shipped-binary fallback)...', flush=True)
    proc = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output / 'build.log').write_text(proc.stdout + '\n' + proc.stderr)
    if proc.returncode:
        raise RuntimeError(f'cargo build failed; see {output / "build.log"}\n{proc.stderr[-4000:]}')
    artifacts = []
    for line in proc.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (message.get('reason') == 'compiler-artifact' and
                message.get('target', {}).get('name') == 'bench_network' and message.get('executable')):
            artifacts.append(message['executable'])
    if not artifacts:
        raise RuntimeError('cargo did not report a bench_network executable; refusing an unverified binary')
    binary = Path(artifacts[-1]).resolve()
    if not binary.is_file():
        raise RuntimeError(f'cargo executable missing: {binary}')
    capabilities = json.loads(subprocess.check_output([str(binary), 'capabilities'], text=True, cwd=root))
    expected = dict(schemes={'roupspa', 'pastau', 'augsso'},
                    phases={'setup', 'authentication', 'password_update'},
                    fanout={'all', 'minimal'}, read_policy={'quorum', 'threshold'},
                    fault_actions={'suppress', 'stop', 'corrupt_partial'})
    if capabilities.get('capabilities_version', 0) < 2:
        raise RuntimeError('bench_network capabilities_version must be at least 2')
    for key, values in expected.items():
        if not values <= set(capabilities.get(key, [])):
            raise RuntimeError(f'bench_network lacks required capability: {key}={values}')
    save_json(output / 'capabilities.json', capabilities)
    environment = json.loads(subprocess.check_output([str(binary), 'check'], text=True, cwd=root))
    save_json(output / 'build-environment.json', environment)
    # Hash the Rust sources and manifests in addition to the executable.
    source_files = sorted(p for p in root.rglob('*') if p.is_file() and
                          (p.suffix == '.rs' or p.name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml')) and
                          not any(part in ('target', '.git', 'network-results') or part.startswith('paper-raw-')
                                  for part in p.relative_to(root).parts))
    source_hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files}
    save_json(output / 'build-provenance.json', dict(
        build_command=command, executable=str(binary),
        executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        source_sha256=source_hashes, validated_at=datetime.now(timezone.utc).isoformat()))
    return binary


def namespace_probe(output):
    if sys.platform != 'linux':
        raise RuntimeError('paper network measurements require Linux network namespaces and tc/netem')
    missing = [name for name in ('ip', 'tc', 'ping') if not shutil.which(name)]
    if missing:
        raise RuntimeError('missing required Linux tools: ' + ', '.join(missing))
    if os.geteuid() != 0:
        raise RuntimeError('namespace runs require a privileged shell. This runner never invokes sudo or prompts for a password. Use DRY_RUN=1 to generate configs, or VALIDATE_ONLY=1 to rebuild/validate without namespaces.')
    name = 'rp-probe-' + uuid.uuid4().hex[:10]
    commands = [['ip', 'netns', 'add', name],
                ['ip', '-n', name, 'link', 'set', 'lo', 'up'],
                ['ip', 'netns', 'exec', name, 'tc', 'qdisc', 'add', 'dev', 'lo', 'root', 'netem', 'delay', '0ms']]
    evidence = []
    created = False
    try:
        for command in commands:
            proc = subprocess.run(command, text=True, capture_output=True)
            evidence.append(dict(command=command, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr))
            if proc.returncode:
                raise RuntimeError('namespace/tc capability probe failed: ' + proc.stderr.strip())
            created = True
    finally:
        if created:
            proc = subprocess.run(['ip', 'netns', 'del', name], text=True, capture_output=True)
            evidence.append(dict(command=['ip', 'netns', 'del', name], returncode=proc.returncode,
                                 stdout=proc.stdout, stderr=proc.stderr))
        save_json(output / 'namespace-probe.json', evidence)


def collect(run_dir, dest):
    """Retain raw rows, independent Rust summaries, metadata and handler logs."""
    dest.mkdir(parents=True, exist_ok=True)
    required = ('raw.jsonl', 'requested-config.json', 'environment.json', 'summary.json', 'session-outcomes.json')
    missing = []
    for name in required:
        source = run_dir / name
        if source.exists():
            shutil.copy2(source, dest / name)
        else:
            missing.append(name)
    for source in run_dir.glob('*-network*.json'):
        (dest / 'network').mkdir(exist_ok=True)
        shutil.copy2(source, dest / 'network' / source.name)
    for filename in ('endpoint.jsonl', 'sync-transports.jsonl', 'process.log'):
        for source in run_dir.rglob(filename):
            target = dest / 'endpoints' / source.relative_to(run_dir)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    return missing


def run_one(row, binary, root, output):
    scratch = Path(row['config']['output_dir'])
    scratch.mkdir(parents=True, exist_ok=True)
    dest = Path(row['raw_dir'])
    dest.mkdir(parents=True, exist_ok=True)
    command = [str(binary), row['command'], '--config', row['config_file']]
    print(f"[{row['suite']}] {row['label']}", flush=True)
    with (dest / 'stdout.log').open('w') as stdout, (dest / 'stderr.log').open('w') as stderr:
        proc = subprocess.run(command, cwd=root, stdout=stdout, stderr=stderr)
    # Even a failed invocation can leave useful durable evidence. It is retained.
    runs = sorted(scratch.glob('run-*'))
    if len(runs) > 1:
        raise RuntimeError(f'expected one new run directory for {scratch}, found {len(runs)}')
    missing = collect(runs[0], dest) if runs else ['run_directory']
    status = dict(suite=row['suite'], label=row['label'], command=command, returncode=proc.returncode,
                  missing_evidence=missing, source_run_dir=str(runs[0]) if runs else None,
                  raw_dir=str(dest), status='completed' if proc.returncode == 0 and not missing else 'runner_failed')
    save_json(dest / 'runner-status.json', status)
    with (output / 'run-status.jsonl').open('a') as handle:
        handle.write(json.dumps(status) + '\n')
    if status['status'] == 'completed' and not enabled('KEEP_FULL_RUNS', True):
        run_dir = runs[0].resolve()
        if not run_dir.is_relative_to((output / '.scratch').resolve()):
            raise RuntimeError(f'refusing cleanup outside this run scratch directory: {run_dir}')
        shutil.rmtree(run_dir)
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', nargs='?', default='all',
                        help='all, paper-minor, roupspa, exp01..exp15, compare-diagnostic, compare-scaling, compare-supported, compare-all, preflight')
    parser.add_argument('preflight_suite', nargs='?', default='all', help='optional suite after preflight')
    args = parser.parse_args()
    root = Path(os.environ.get('ROOT', Path(__file__).resolve().parents[1])).resolve()
    if not (root / 'Cargo.toml').is_file():
        raise RuntimeError(f'Cargo.toml is missing under ROOT={root}')
    preflight = enabled('PREFLIGHT') or args.mode.lower() == 'preflight'
    mode = args.preflight_suite if args.mode.lower() == 'preflight' else args.mode
    default_name = ('paper-preflight-' if preflight else 'paper-raw-') + datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    output = Path(os.environ.get('OUT_ROOT', str(root / default_name))).resolve()
    if output.exists() and any(output.iterdir()):
        raise RuntimeError(f'OUT_ROOT must be new or empty (existing evidence will not be overwritten): {output}')
    plan = write_matrix(output, mode, preflight)
    with (output / 'MANIFEST.tsv').open('w', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t')
        writer.writerow(['suite', 'label', 'command', 'n_sp', 't_sp', 'q_sp', 'phase', 'schemes',
                         'fanout', 'read_policy', 'warmups', 'samples', 'repetitions', 'read_size', 'warnings', 'config', 'raw_dir'])
        for row in plan['configs']:
            c = row['config']
            writer.writerow([row['suite'], row['label'], row['command'], c['n_sp'], c['t_sp'], c['q_sp'],
                             c['phase'], ','.join(c['schemes']), c['fanout'], c['read_policy'],
                             c['warmups'], c['samples'], c['repetitions'], row['read_size'], ' | '.join(row['warnings']), row['config_file'], row['raw_dir']])
    print(f"Prepared {len(plan['configs'])} configurations: {output}", flush=True)
    if enabled('DRY_RUN'):
        warning_count = sum(bool(row['warnings']) for row in plan['configs'])
        print(f'{warning_count} configurations carry interpretation warnings; see plan.json or MANIFEST.tsv.')
        print('DRY_RUN: configuration generation only; no build, validation, or measurements performed.')
        return 0
    failures = []
    try:
        binary = build(root, output)
        validation = []
        for row in plan['configs']:
            proc = subprocess.run([str(binary), 'validate', '--config', row['config_file']], cwd=root,
                                  text=True, capture_output=True)
            validation.append(dict(config=row['config_file'], returncode=proc.returncode,
                                   stdout=proc.stdout, stderr=proc.stderr))
        save_json(output / 'validation.json', validation)
        bad = [v for v in validation if v['returncode']]
        if bad:
            raise RuntimeError(f"{len(bad)} configuration(s) failed validation; see {output / 'validation.json'}")
        if enabled('VALIDATE_ONLY'):
            print('VALIDATE_ONLY: rebuilt binary, capabilities and all configurations verified; no network runs.')
            return 0
        namespace_probe(output)
        for row in plan['configs']:
            status = run_one(row, binary, root, output)
            if status['status'] != 'completed':
                failures.append(status)
                if not enabled('CONTINUE_ON_ERROR'):
                    break
    finally:
        summarize_tree(output)
        print(f'Evidence: {output}\nAvailability: {output / "analysis/availability.csv"}', flush=True)
    if failures:
        raise RuntimeError(f'{len(failures)} runner invocation(s) failed; raw/partial evidence and logs preserved')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'paper runner: {error}', file=sys.stderr)
        sys.exit(1)
