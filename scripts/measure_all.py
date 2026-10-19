#!/usr/bin/env python3
"""Unattended, evidence-checked measurement of the unchanged benchmark engines."""
from __future__ import annotations
import argparse
from collections import Counter
import copy
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import uuid

from measurement_process import run_logged, make_isolated_command, make_isolation_probe_command
from paper_configs import selected_matrix
from pdf_comparison_plan import comparison_jobs, normalize_dat
from summarize_raw import population, summarize_file

ROOT = Path(__file__).resolve().parents[1]
SETTINGS = ('PDF_SAMPLES', 'PDF_WARMUPS', 'PDF_PROC_SAMPLES', 'PDF_PROC_WARMUPS', 'PDF_OFFLINE',
            'DELTA_BASE', 'TIMEOUT_BASE', 'RETRY_BASE', 'LOSS_TIMEOUT', 'COMPARE_TIMEOUT', 'SCALING_TIMEOUT',
            'MEASUREMENT_PREFLIGHT', 'MEASUREMENT_JOB_TIMEOUT_SECONDS',
            'MEASUREMENT_PREFLIGHT_TIMEOUT_SECONDS', 'MEASUREMENT_BUILD_TIMEOUT_SECONDS') + tuple(
                f'{policy}_{field}' for policy in ('PERF', 'FAULT', 'RECOVERY', 'SCALING')
                for field in ('WARMUPS', 'SAMPLES', 'REPS'))


def now():
    return datetime.now(timezone.utc).isoformat()


def save(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(obj, indent=2) + '\n')
    temporary.replace(path)


def read(path):
    return json.loads(Path(path).read_text())


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_hashes(root=ROOT):
    files = []
    for p in root.rglob('*'):
        if not p.is_file() or any(part in ('target', '.git', '__pycache__', 'measurements', 'network-results')
                                  or part.startswith('paper-raw-') for part in p.relative_to(root).parts):
            continue
        if p.suffix in ('.rs', '.py', '.sh') or p.name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'):
            files.append(p)
    return {str(p.relative_to(root)): digest(p) for p in sorted(files)}


def positive(env, key, default):
    value = int(env.get(key, default))
    if value <= 0:
        raise ValueError(f'{key} must be positive')
    return value


def make_plan(env=None):
    env = os.environ if env is None else env
    preflight = str(env.get('MEASUREMENT_PREFLIGHT', '0'))
    if preflight not in ('0', '1'):
        raise ValueError('MEASUREMENT_PREFLIGHT must be 0 or 1')
    jobs = []
    for row in selected_matrix('roupspa', env, False):
        jobs.append(dict(id=f"{row['suite']}-{row['label']}", group='roupspa_exp01_exp15',
                         engine='network', **row))
    jobs += [dict(engine='pdf', **j) for j in comparison_jobs(False, env)]
    if len({j['id'] for j in jobs}) != len(jobs):
        raise ValueError('duplicate measurement IDs')
    return dict(schema_version=1, jobs=jobs, settings={k: env[k] for k in SETTINGS if k in env},
                preflight=preflight == '1', timeouts=dict(
                    job=positive(env, 'MEASUREMENT_JOB_TIMEOUT_SECONDS', 14400),
                    preflight=positive(env, 'MEASUREMENT_PREFLIGHT_TIMEOUT_SECONDS', 1800),
                    build=positive(env, 'MEASUREMENT_BUILD_TIMEOUT_SECONDS', 7200)),
                notes=['PDF comparisons use measured historical cores plus modeled network costs.',
                       'The 15 RoUpSPA experiments use the process/network implementation.',
                       'Complete evidence does not imply protocol success; aborts and recovery remain separate.',
                       'PDF PASTA-U provider data are component measurements, not invented aggregate quantiles.'])


def checked(command, logdir, timeout, cwd=ROOT):
    result = run_logged(command, cwd, logdir, timeout)
    save(Path(logdir) / 'process.json', result)
    if result['timed_out'] or result['rc']:
        raise RuntimeError(f"{'timeout' if result['timed_out'] else 'exit '+str(result['rc'])}; see {logdir}")
    return result


def build(output, timeout):
    if not shutil.which('cargo'):
        raise RuntimeError('cargo missing; install the pinned toolchain and dependencies first')
    command = ['cargo', 'build', '--locked', '--release', '--bin', 'bench_network', '--bin',
               'bench_unified', '--message-format=json-render-diagnostics']
    checked(command, output, timeout)
    binaries = {}
    for line in (output / 'stdout.log').read_text().splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        name = message.get('target', {}).get('name')
        if message.get('reason') == 'compiler-artifact' and name in ('bench_network', 'bench_unified') and message.get('executable'):
            binaries[name] = str(Path(message['executable']).resolve())
    if set(binaries) != {'bench_network', 'bench_unified'}:
        raise RuntimeError('cargo did not report both executables; no prebuilt fallback is permitted')
    # Keep a private copy: another Cargo invocation must not replace a binary
    # halfway through this run.
    frozen = output / 'executables'
    frozen.mkdir()
    for name, path in list(binaries.items()):
        target = frozen / name
        shutil.copy2(path, target)
        binaries[name] = str(target.resolve())
    checked([binaries['bench_network'], 'capabilities'], output / 'capabilities', 60)
    caps = json.loads((output / 'capabilities/stdout.log').read_text())
    if caps.get('capabilities_version', 0) < 2 or 'roupspa' not in caps.get('schemes', []):
        raise RuntimeError('bench_network lacks required capabilities')
    save(output / 'provenance.json', dict(command=command, executables=binaries,
         executable_sha256={name: digest(path) for name, path in binaries.items()}, at=now()))
    return binaries


def expected_keys(config):
    return {(profile['name'], round(100 * (1-(1-profile['loss_percent']/100)*(1-loss/100)), 10),
             scheme, config['phase'], rep, sample)
            for profile in config['profiles'] for loss in config['loss_levels']
            for scheme in config['schemes'] for rep in range(config['repetitions'])
            for sample in range(config['warmups'], config['warmups'] + config['samples'])}


def verify_network(stage, job):
    config = read(stage / 'config.json')
    planned = copy.deepcopy(job['config'])
    planned.update(output_dir=str(stage / 'native'), state_dir='network-state')
    if config != planned:
        raise ValueError('saved config differs from planned configuration')
    runs = list((stage / 'native').glob('run-*'))
    if len(runs) != 1:
        raise ValueError(f'expected one native run, found {len(runs)}')
    run = runs[0]
    for name in ('raw.jsonl', 'requested-config.json', 'environment.json', 'summary.json', 'session-outcomes.json'):
        if not (run / name).is_file():
            raise ValueError(f'missing native evidence: {name}')
        if name != 'raw.jsonl':
            read(run / name)
    if read(run / 'requested-config.json') != config:
        raise ValueError('native requested-config differs from submitted configuration')
    seen = Counter()
    for line in (run / 'raw.jsonl').read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if population(row) != 'measured':
            continue
        result = row['result']
        if result['outcome'] not in ('completed', 'cleanly_aborted', 'unresolved', 'failed'):
            raise ValueError(f"unrecognized outcome {result['outcome']}")
        seen[(row['profile'], round(float(row['loss_percent']), 10), result['scheme'],
              result['phase'], row['repetition'], row['sample'])] += 1
    expected = expected_keys(config)
    if set(seen) != expected or any(count != 1 for count in seen.values()):
        raise ValueError(f'raw coverage mismatch: missing={len(expected-set(seen))}, '
                         f'extra={len(set(seen)-expected)}, duplicates={sum(v-1 for v in seen.values())}')
    summary = summarize_file(run / 'raw.jsonl', job['suite'], job['label'], config)
    if not summary['availability'] or any(r['evidence_status'] != 'complete' for r in summary['availability']):
        raise ValueError('incomplete network evidence')
    save(stage / 'normalized.json', summary)
    return summary


def verify(stage, job):
    if job['engine'] == 'network':
        return verify_network(stage, job)
    data = normalize_dat(stage / 'raw.dat', job)
    save(stage / 'normalized.json', data)
    return data


def prepare_network(stage, job):
    config = copy.deepcopy(job['config'])
    config.update(output_dir=str(stage / 'native'), state_dir='network-state')
    save(stage / 'config.json', config)
    return stage / 'config.json'


def run_stage(stage, job, binaries, timeout, validate=False):
    stage.mkdir(parents=True, exist_ok=True)
    if job['engine'] == 'network':
        config = prepare_network(stage, job)
        command = [binaries['bench_network'], 'validate' if validate else job['command'], '--config', str(config)]
        if not validate:
            command = make_isolated_command(command)
    else:
        command = [binaries['bench_unified'], *job['flags'], '--out', str(stage / 'raw.dat')]
        if validate:
            command += ['--dry-run']
    checked(command, stage, min(timeout, 120) if validate else timeout)
    if not validate:
        verify(stage, job)


def csv_write(path, rows, fields):
    with Path(path).open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v
                             for k, v in row.items() if k in fields})


def report(output, state, final=False):
    counts = dict(Counter(j['status'] for j in state['jobs']))
    state.update(updated_at=now(), counts=counts)
    save(output / 'progress.json', state)
    csv_write(output / 'job-status.csv', state['jobs'], ['id', 'group', 'status', 'attempt', 'stage', 'error'])
    failed = [j for j in state['jobs'] if j['status'] not in ('complete', 'pending', 'running')]
    csv_write(output / 'FAILED_JOBS.csv', failed, ['id', 'group', 'status', 'error'])
    text = ['# Measurement status', '', f"State: {state['status']}",
            f"Complete jobs: {counts.get('complete', 0)} / {len(state['jobs'])}",
            '', 'Complete means all planned evidence was captured, not that every protocol attempt succeeded.',
            'See job-status.csv and FAILED_JOBS.csv for missing measurements.',
            'Raw files and earlier attempts remain under jobs/.', '',
            'PDF comparisons: measured historical cores plus modeled LAN/WAN. The current network protocol is tested separately in exp01–exp15.',
            'Provider component medians are retained with their scope; do not treat their sums as empirical phase quantiles.', '']
    if state.get('error'):
        text += ['Run error: ' + state['error'], '']
    (output / 'RESULTS_SUMMARY.md').write_text('\n'.join(text))
    if final:
        save(output / 'FINAL_STATUS.json', state)
        comparisons, network = [], []
        for job in state['jobs']:
            if job['status'] != 'complete':
                continue
            data = read(output / job['stage'] / 'normalized.json')
            if job['group'] == 'roupspa_exp01_exp15':
                network.append(data)
            else:
                comparisons.extend(data)
        save(output / 'network_summaries.json', network)
        fields = ['job_id', 'group', 'suite', 'scheme', 'n', 't', 'q', 'comparison_q', 'unavailable',
                  'phase', 'panel', 'raw_phase', 'raw_kind', 'samples', 'warmups', 'p50_ns', 'p50_ms',
                  'statistic', 'components_for', 'provider_scope', 'measurement_model', 'selected_for_pdf', 'warnings']
        csv_write(output / 'comparisons.csv', comparisons, fields)


def preflight_job(job, env):
    if job['engine'] == 'pdf':
        return next(dict(engine='pdf', **j) for j in comparison_jobs(True, env) if j['id'] == job['id'])
    result = copy.deepcopy(job)
    result['config'].update(samples=1, warmups=0, repetitions=1)
    return result


def record_lock_contention(output):
    """Do not overwrite an active worker's progress when resume is repeated."""
    state = read(output / 'progress.json')
    message = 'Another measurement worker is active. Resume this run after it finishes.'
    if state['status'] != 'RUNNING':
        state.update(status='BLOCKED', error=message)
        report(output, state, final=True)
    return message


def worker(output, lock_path=None):
    # SIGTERM must unwind the subprocess context, so descendants and private namespaces are released.
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(128 + signum))
    lock_path = Path(lock_path or '/run/lock/roupspa-measurements.lock')
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock = lock_path.open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(record_lock_contention(output), flush=True)
        lock.close()
        return 2
    plan = read(output / 'plan.json')
    state = read(output / 'progress.json')
    state.update(status='RUNNING', pid=os.getpid(), error=None)
    report(output, state)
    launch = output / ('launch-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    launch.mkdir()
    try:
        if digest(output / 'plan.json') != read(output / 'plan-sha256.json'):
            raise RuntimeError('saved plan changed; start a separate run')
        if [j['id'] for j in plan['jobs']] != [j['id'] for j in state['jobs']]:
            raise RuntimeError('progress jobs do not match the saved plan')
        if source_hashes() != read(output / 'source-sha256.json'):
            raise RuntimeError('source changed since planning; start a new run instead of mixing implementations')
        checked([sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts', '-p', 'test_*.py'],
                launch / 'python-tests', 180)
        binaries = build(launch / 'build', plan['timeouts']['build'])
        executable_hashes = {name: digest(path) for name, path in binaries.items()}
        previous = output / 'executable-sha256.json'
        if previous.exists() and read(previous) != executable_hashes:
            raise RuntimeError('rebuilt executables differ from this run; start a new run to avoid mixing builds')
        save(previous, executable_hashes)
        if source_hashes() != read(output / 'source-sha256.json'):
            raise RuntimeError('source changed while building')
        network_error = None
        try:
            if not shutil.which('ping'):
                raise RuntimeError('ping missing')
            checked(make_isolation_probe_command(), launch / 'isolation-probe', 120)
        except Exception as exc:
            network_error = str(exc)
            print('Network jobs blocked, independent PDF jobs will continue: ' + network_error, flush=True)
        # Validate every coordinate before measuring anything. This is cheap and has no network effects.
        validation_errors = {}
        for job in plan['jobs']:
            try:
                run_stage(launch / 'validation' / job['id'], job, binaries, 120, validate=True)
            except Exception as exc:
                validation_errors[job['id']] = str(exc)
        for job, status in zip(plan['jobs'], state['jobs']):
            if status['status'] == 'complete':
                try:
                    verify(output / status['stage'], job)
                    continue
                except Exception as exc:
                    status.update(status='evidence_invalid', error=str(exc))
            status.update(status='running', error=None, attempt=status.get('attempt', 0) + 1)
            attempt = output / 'jobs' / job['id'] / f"attempt-{status['attempt']:03}"
            attempt.mkdir(parents=True, exist_ok=False)
            status['stage'] = str((attempt / 'full').relative_to(output))
            report(output, state)
            print(f"[{job['id']}] attempt {status['attempt']}", flush=True)
            try:
                if job['id'] in validation_errors:
                    raise RuntimeError('validation failed: ' + validation_errors[job['id']])
                if job['engine'] == 'network' and network_error:
                    raise RuntimeError('network unavailable: ' + network_error)
                if plan['preflight']:
                    run_stage(attempt / 'preflight', preflight_job(job, plan['settings']), binaries, plan['timeouts']['preflight'])
                run_stage(attempt / 'full', job, binaries, plan['timeouts']['job'])
                status.update(status='complete')
            except Exception as exc:
                status.update(status='failed', error=str(exc))
                print(f"  FAILED: {exc}", flush=True)
            report(output, state)
        state['status'] = 'COMPLETE' if all(j['status'] == 'complete' for j in state['jobs']) else 'INCOMPLETE'
    except BaseException as exc:
        state.update(status='INTERRUPTED' if isinstance(exc, (SystemExit, KeyboardInterrupt)) else 'BLOCKED', error=str(exc))
        for job in state['jobs']:
            if job['status'] == 'running':
                job.update(status='interrupted', error='worker interrupted')
        print(f"{state['status']}: {exc}", flush=True)
    finally:
        try:
            report(output, state, final=True)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()
    print(f"{state['status']}: {output / 'RESULTS_SUMMARY.md'}", flush=True)
    return 0 if state['status'] == 'COMPLETE' else 1


def privileged():
    if sys.platform != 'linux':
        raise RuntimeError('measurements require Linux; plan/status can be used without privileges')
    if os.geteuid() == 0:
        return
    if not shutil.which('sudo'):
        raise RuntimeError('run in a privileged Linux shell; sudo is missing')
    allowed = SETTINGS + ('PATH', 'CARGO_HOME', 'RUSTUP_HOME', 'RUSTC', 'LD_LIBRARY_PATH')
    values = {k: os.environ[k] for k in allowed if k in os.environ}
    values.setdefault('CARGO_HOME', str(Path.home() / '.cargo'))
    values.setdefault('RUSTUP_HOME', str(Path.home() / '.rustup'))
    print('One initial sudo authorization is needed for network namespaces. No later prompts.', flush=True)
    os.execvp('sudo', ['sudo', '--', 'env', *[k+'='+v for k, v in values.items()],
                       sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])


def launch(output):
    with (output / 'master.log').open('ab') as log:
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '_worker', str(output)],
                                 cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    save(output / 'launcher.json', dict(pid=child.pid, started_at=now()))
    print(f'Started PID {child.pid}. Worker continues after terminal exit; the host must remain powered on and awake.\n'
          f'Results: {output}\nLog: {output / "master.log"}\n'
          f'Status: bash run_measurements.sh status "{output}"', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['start', 'run', 'resume', 'status', 'plan', '_worker'])
    parser.add_argument('path', nargs='?')
    args = parser.parse_args()
    if args.command == 'plan':
        print(json.dumps(make_plan(), indent=2))
        return 0
    if args.command == 'status':
        if not args.path:
            parser.error('status requires a run directory')
        print(json.dumps(read(Path(args.path).resolve() / 'progress.json'), indent=2))
        return 0
    privileged()
    if args.command in ('resume', '_worker'):
        if not args.path:
            parser.error(args.command + ' requires a run directory')
        output = Path(args.path).resolve()
        if args.command == 'resume' and source_hashes() != read(output / 'source-sha256.json'):
            raise RuntimeError('source changed; use start for a separate run')
    else:
        output = Path(args.path).resolve() if args.path else ROOT / 'measurements' / ('run-' + datetime.now().strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:6])
        output.mkdir(parents=True, exist_ok=False)
        plan = make_plan()
        save(output / 'plan.json', plan)
        save(output / 'plan-sha256.json', digest(output / 'plan.json'))
        save(output / 'source-sha256.json', source_hashes())
        state = dict(status='QUEUED', created_at=now(), jobs=[dict(id=j['id'], group=j['group'],
                      status='pending', attempt=0, stage=None, error=None) for j in plan['jobs']])
        report(output, state)
    if args.command in ('start', 'resume'):
        launch(output)
        return 0
    return worker(output)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        raise SystemExit(1)
