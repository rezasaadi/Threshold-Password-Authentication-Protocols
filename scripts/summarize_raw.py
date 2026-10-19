#!/usr/bin/env python3
"""Summarize raw evidence without mixing failed attempts, fixtures or recovery.

Usage: python3 scripts/summarize_raw.py --input paper-raw-DATE [--output DIR]
A single raw.jsonl path is also accepted (requested-config.json is read beside it).
Only the Python standard library is required. Missing telemetry is never a zero.
"""
import argparse
from collections import Counter, defaultdict
import csv
import json
import math
from pathlib import Path
import statistics

TIMINGS = ('end_to_end', 'end_to_end_excl_terminal_wait', 'end_to_end_excl_drain',
           'client', 'quorum', 'provider_handler', 'login_handler', 'handler',
           'terminal_delivery_wait', 'terminal_handler', 'drain', 'toprf_combine',
           'repair', 'process_wall')
COUNTERS = ('read_replies_required', 'toprf_subsets_tried', 'toprf_consistency_checks',
            'id_candidates', 'discards', 'discard_undelivered', 'fanout_extensions',
            'sent_bytes', 'received_bytes', 'sent_messages', 'received_messages',
            'application_bytes', 'application_messages', 'retries', 'timeouts')
RECOVERY_SUFFIXES = ('-resume', '-terminal-recovery', '-after-restart')
RECOVERY_PHASES = ('resume', 'retry_terminal', 'discard')


def population(row):
    result = row['result']
    recovery = (row.get('run_id', '').endswith(RECOVERY_SUFFIXES)
                or result.get('phase') in RECOVERY_PHASES
                or (row.get('fixture') and result.get('metrics', {}).get('repair_ns', 0) > 0))
    kind = 'recovery' if recovery else ('fixture' if row.get('fixture') else 'measured')
    return 'warmup_' + kind if row.get('warmup') else kind


def numeric(value):
    return value if (isinstance(value, (int, float)) and not isinstance(value, bool)
                     and math.isfinite(value) and value >= 0) else None


def metric(row, name):
    result = row['result']
    m = result.get('metrics', {})
    # Fixture failures produce placeholder measured records; retain outcomes,
    # but do not turn these placeholders into zero-latency successes/failures.
    if result.get('session') == 'fixture-blocked':
        return None
    unavailable = result.get('client_measurement_unavailable', False)
    if name in ('provider_handler', 'login_handler', 'process_wall'):
        return numeric(row.get(name + '_ns'))
    if name == 'end_to_end':
        return numeric(m.get('end_to_end_ns'))
    if name in ('sent_bytes', 'received_bytes', 'sent_messages', 'received_messages'):
        return numeric(m.get(name))
    if name in ('application_bytes', 'application_messages'):
        suffix = name.removeprefix('application_')
        a, b = numeric(m.get('sent_' + suffix)), numeric(m.get('received_' + suffix))
        return None if a is None or b is None else a + b
    if name == 'handler':
        return numeric(m.get('handler_ns'))
    if unavailable:
        return None
    if name.startswith('end_to_end_excl_'):
        subtract = 'terminal_ns' if name.endswith('terminal_wait') else 'drain_ns'
        a, b = numeric(m.get('end_to_end_ns')), numeric(m.get(subtract))
        return None if a is None or b is None else max(0, a - b)
    name = 'terminal' if name == 'terminal_delivery_wait' else name
    return numeric(m.get(name if name in COUNTERS else name + '_ns'))


def stats(values, total=None):
    present = sorted(v for v in values if v is not None)
    count = len(present)
    def percentile(percent):
        return present[max(0, math.ceil(count * percent / 100) - 1)] if count else None
    return dict(samples=count, missing=(len(values) if total is None else total) - count,
                p50=percentile(50), p95=percentile(95),
                mean=statistics.mean(present) if count else None,
                sd=statistics.stdev(present) if count >= 2 else None,
                min=present[0] if count else None, max=present[-1] if count else None,
                sum=sum(present) if count else None)


def summarize_group(rows, kind):
    outcomes = Counter(r['result']['outcome'] for r in rows)
    completed = [r for r in rows if r['result']['outcome'] == 'completed']
    timings = {}
    for name in TIMINGS:
        timings[name + '_ns'] = dict(
            all_attempts=stats([metric(r, name) for r in rows]),
            completed=stats([metric(r, name) for r in completed]))
    counters = {name: dict(all_attempts=stats([metric(r, name) for r in rows]),
                           completed=stats([metric(r, name) for r in completed]))
                for name in COUNTERS}
    return dict(attempts=len(rows), completed=len(completed), outcomes=dict(sorted(outcomes.items())),
                success_rate=len(completed)/len(rows) if rows else None,
                blocked_by_fixture=sum(r['result'].get('session') == 'fixture-blocked' for r in rows),
                without_client_telemetry=sum(bool(r['result'].get('client_measurement_unavailable')) for r in rows),
                reasons=dict(Counter(r['result']['reason'] for r in rows if r['result'].get('reason'))),
                timings=timings, counters=counters,
                handler_scope='interval_delta' if kind in ('measured', 'warmup_measured') else 'cumulative_snapshot',
                measurement_sources=dict(Counter(r['result'].get('measurement_source', 'unspecified') for r in rows)))


def read_json(path, default=None):
    return json.loads(path.read_text()) if path.exists() else default


def summarize_file(raw_path, suite, label, config=None):
    raw_path = Path(raw_path)
    config = config or read_json(raw_path.parent / 'requested-config.json', {})
    groups = defaultdict(list)
    rows = []
    if raw_path.exists():
        for line_no, line in enumerate(raw_path.read_text().splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                result = row['result']
                key = (population(row), result['scheme'], result['phase'],
                       row['profile'], float(row['loss_percent']))
                groups[key].append(row)
                rows.append(row)
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f'{raw_path}:{line_no}: invalid raw record: {exc}') from exc
    summary = dict(schema_version=2, suite=suite, label=label, raw_file=str(raw_path),
                   raw_available=raw_path.exists(), config=config, raw_records=len(rows), groups=[])
    summary['notes'] = [
        'Success means outcome=completed; cleanly_aborted and unresolved remain distinct unsuccessful outcomes.',
        'All-attempt and completed-only timing distributions are separate. Time units are nanoseconds.',
        'p50/p95 use nearest rank; sd is sample standard deviation (null below two observations).',
        'Missing legacy metrics and absent client telemetry are excluded, never imputed as zero.',
        'end_to_end may be external process wall after a client crash; measurement_sources records this.',
        'client is wall time minus instrumented waits, not a CPU-time measurement.',
        'Endpoint handler totals for fixture/recovery rows are cumulative snapshots, not per-phase durations.',
        'Application traffic excludes TCP/IP headers and kernel retransmissions; crashed-client prefix accounting may be incomplete.',
        'Threshold reads are an ablation; successful completion does not establish protocol security.',
    ]
    for key, bucket in sorted(groups.items()):
        kind, scheme, phase, profile, loss = key
        summary['groups'].append(dict(population=kind, scheme=scheme, phase=phase,
                                      profile=profile, loss_percent=loss, **summarize_group(bucket, kind)))
    expected = {}
    for scheme in config.get('schemes', []):
        for p in config.get('profiles', []):
            for loss in config.get('loss_levels', []):
                actual = 100 * (1 - (1 - p['loss_percent']/100) * (1 - loss/100))
                expected[(scheme, config['phase'], p['name'], round(actual, 10))] = (
                    config['samples'] * config['repetitions'])
    actual_groups = {(g['scheme'], g['phase'], g['profile'], round(g['loss_percent'], 10)): g
                     for g in summary['groups'] if g['population'] == 'measured'}
    availability = []
    for key in sorted(expected.keys() | actual_groups.keys()):
        group = actual_groups.get(key, {})
        attempts = group.get('attempts', 0)
        wanted = expected.get(key)
        availability.append(dict(suite=suite, label=label, scheme=key[0], phase=key[1], profile=key[2],
                                 loss_percent=key[3], expected_attempts=wanted, attempts=attempts,
                                 completed=group.get('completed', 0), success_rate=group.get('success_rate'),
                                 evidence_status=('unplanned' if wanted is None else
                                                  'complete' if attempts == wanted else
                                                  'missing' if attempts == 0 else
                                                  'incomplete' if attempts < wanted else 'excess'),
                                 outcomes=group.get('outcomes', {})))
    summary['availability'] = availability
    return summary


def discover(input_path):
    input_path = Path(input_path).resolve()
    if input_path.is_file():
        return [dict(suite=input_path.parent.parent.name, label=input_path.parent.name,
                     raw_path=input_path, config=None)]
    plan = read_json(input_path / 'plan.json')
    if plan:
        return [dict(suite=r['suite'], label=r['label'],
                     raw_path=input_path / 'raw' / r['suite'] / r['label'] / 'raw.jsonl',
                     config=r['config']) for r in plan['configs']]
    paths = sorted(input_path.rglob('raw.jsonl'))
    # A paper output includes retained scratch copies: only use collected raw.
    if (input_path / 'raw').is_dir():
        paths = sorted((input_path / 'raw').rglob('raw.jsonl'))
    return [dict(suite=p.parent.parent.name, label=p.parent.name, raw_path=p, config=None) for p in paths]


def summarize_tree(input_path, output=None):
    input_path = Path(input_path).resolve()
    if not input_path.exists():
        raise FileNotFoundError(input_path)
    output = Path(output) if output else (input_path.parent if input_path.is_file() else input_path) / 'analysis'
    output.mkdir(parents=True, exist_ok=True)
    index, availability = [], []
    for item in discover(input_path):
        summary = summarize_file(**item)
        dest = output / summary['suite'] / (summary['label'] + '.json')
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(summary, indent=2, allow_nan=False) + '\n')
        index.append(dict(suite=summary['suite'], label=summary['label'],
                          summary=str(dest.relative_to(output)), raw_available=summary['raw_available'],
                          raw_records=summary['raw_records'], availability=summary['availability']))
        availability.extend(summary['availability'])
    (output / 'index.json').write_text(json.dumps(dict(schema_version=2, configurations=index), indent=2) + '\n')
    columns = ['suite', 'label', 'scheme', 'phase', 'profile', 'loss_percent', 'expected_attempts',
               'attempts', 'completed', 'success_rate', 'evidence_status', 'outcomes']
    with (output / 'availability.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in availability:
            writer.writerow(dict(row, outcomes=json.dumps(row['outcomes'], sort_keys=True)))
    lines = ['# Measurement availability', '',
             'Completion rate uses all measured attempts. Recovery and fixture outcomes are in the per-configuration JSON.', '',
             '| Experiment/config | Scheme | Phase | Profile/loss | Available/expected | Completed | Rate | Evidence |',
             '| --- | --- | --- | --- | ---: | ---: | ---: | --- |']
    for row in availability:
        rate = 'N/A' if row['success_rate'] is None else f"{100*row['success_rate']:.1f}%"
        lines.append(f"| {row['suite']}/{row['label']} | {row['scheme']} | {row['phase']} | {row['profile']}/{row['loss_percent']:g}% | {row['attempts']}/{row['expected_attempts'] if row['expected_attempts'] is not None else '?'} | {row['completed']} | {rate} | {row['evidence_status']} |")
    (output / 'availability.md').write_text('\n'.join(lines) + '\n')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    print(summarize_tree(args.input, args.output))
