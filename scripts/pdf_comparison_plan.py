#!/usr/bin/env python3
"""Exact reference-paper comparison grids for the unchanged bench_unified engine.

These are measured protocol cores plus MODELLED LAN/WAN, not process-network
measurements. The separate RoUpSPA exp01..exp15 suite uses bench_network.
"""
from __future__ import annotations

import math
import os
from pathlib import Path

PDF_SOURCE = 'RoUpSPA_step1_red_step2_blue(1).pdf'
PDF_SHA256 = 'fc50a1d1cd3f1f9e307dc1dd2cd793cc6d52822ec177cf66ace85fa5b39f4665'
DEPLOYMENT = ((3, 2), (5, 2), (5, 4), (7, 2), (7, 3), (7, 5), (7, 7))
FIXED_THRESHOLD = tuple((10, t) for t in range(1, 11))
PROPORTIONAL = tuple((n, 3 * n // 5) for n in range(10, 101, 10))
RESILIENCE = ((3, 2, 3), (5, 3, 4), (7, 4, 6), (7, 5, 6), (10, 6, 8))
NETWORK_FLAGS = ['--net', 'all', '--lan-rtt-ms', '0.5', '--lan-jitter-ms', '0.05',
                 '--lan-bw-mbps', '1000', '--wan-rtt-ms', '60', '--wan-jitter-ms', '5',
                 '--wan-bw-mbps', '50', '--overhead-bytes', '64']
BASELINE_PHASES = ('reg', 'auth', 'pwdupd')
RESILIENCE_PHASES = ('reg', 'secupd', 'pwdupd')
CORE_WARNING = ('Unchanged historical RoUpSPA core with modeled network stages; '
                'does not exercise the current process-network read-size, password-update '
                'consistency guard, durable terminal handlers, or fail-closed recovery. '
                'Do not use these rows as successful current-process measurements.')
# No per-phase PASTA-U provider aggregate is emitted. Preserve its primitives.
PROVIDER_COMPONENTS = {
    'pastau': {'reg': ('reg_store',), 'auth': ('auth_db_get', 'auth_respond'),
               'pwdupd': ('auth_respond', 'update_respond', 'update_handle')},
    'augsso': {'reg': ('reg_store',), 'auth': ('auth_total_p50sum',),
               'pwdupd': ('update_total_p50sum',)},
}


def _integer(env, name, default, minimum):
    value = str(env.get(name, default))
    try:
        result = int(value)
    except ValueError as exc:
        raise ValueError(f'{name} must be an integer, got {value!r}') from exc
    if result < minimum:
        raise ValueError(f'{name} must be >= {minimum}')
    return result


def comparison_jobs(preflight=False, env=None):
    """Return 81 baseline + 10 resilience jobs; flags exclude --out.

    PDF pp33-34 specify 50 warmups / 200 samples. Provider calibration counts
    are not stated in the PDF: use matching 50/200 explicitly, not the binary's
    implicit 200/1000. PDF_OFFLINE defaults to max from the original repository
    README (Quick start); the PDF itself does not specify that parameter.
    """
    env = os.environ if env is None else env
    samples = _integer(env, 'PDF_SAMPLES', 200, 1)
    warmups = _integer(env, 'PDF_WARMUPS', 50, 0)
    proc_samples = _integer(env, 'PDF_PROC_SAMPLES', samples, 1)
    proc_warmups = _integer(env, 'PDF_PROC_WARMUPS', warmups, 0)
    offline = str(env.get('PDF_OFFLINE', 'max')).lower()
    if offline not in ('max', 'none', '0'):
        raise ValueError('PDF_OFFLINE must be max, none, or 0; other counts are not valid for every PDF tuple')
    if preflight:
        samples, warmups, proc_samples, proc_warmups = 1, 0, 1, 0
    jobs = []
    grids = [('deployment', DEPLOYMENT), ('fixed_threshold', FIXED_THRESHOLD),
             ('proportional', PROPORTIONAL)]
    def add(suite, scheme, n, t, q=None):
        resilient = suite == 'resilience'
        phases = RESILIENCE_PHASES if resilient else BASELINE_PHASES
        modern = scheme in ('upspa', 'roupspa')
        kind = 'client,provider,full-net' if modern else 'proto,sp,full'
        flags = ['--scheme', scheme, '--kind', kind, '--ops', ','.join(phases),
                 '--nsp', str(n), '--tsp', str(t), '--sample-size', str(samples),
                 '--warmup-iters', str(warmups), '--proc-samples', str(proc_samples),
                 '--proc-warmup', str(proc_warmups)] + NETWORK_FLAGS
        if scheme == 'roupspa':
            flags += ['--qsp', str(q), '--offline', offline]
        panels = ['client', 'lan', 'wan'] if resilient else ['client', 'provider', 'lan', 'wan']
        suffix = f'-q{q}' if q is not None else ''
        jobs.append(dict(
            id=f'pdf-{suite}-{scheme}-n{n}-t{t}{suffix}',
            group='upspa_vs_roupspa' if resilient else 'upspa_vs_pastau_vs_augsso',
            suite=suite, scheme=scheme, n=n, t=t, q=q, phases=list(phases), flags=flags,
            samples=samples, warmups=warmups, proc_samples=proc_samples, proc_warmups=proc_warmups,
            offline=offline if scheme == 'roupspa' else 'none', preflight=bool(preflight),
            measurement_model='measured_core_plus_modeled_network',
            expected={phase: list(panels) for phase in phases},
            provider_panel='components_only' if scheme == 'pastau' else
                           ('native_per_provider_components' if scheme == 'augsso' else 'aggregate_provider_processing'),
            provenance=dict(pdf=PDF_SOURCE, pdf_sha256=PDF_SHA256, printed_pages=[33, 34, 40, 41] if resilient else [33, 34, 35, 36, 37, 38, 39],
                            figures=[16, 17, 18] if resilient else list(range(7, 16)),
                            calibration='PDF does not specify calibration sample counts; explicit runner setting',
                            offline='Original repository README Quick start explicitly uses --offline max; PDF count unspecified' if scheme == 'roupspa' else 'fully available baseline'),
            warnings=[CORE_WARNING] if scheme == 'roupspa' else [],
        ))
    for suite, grid in grids:
        for n, t in grid:
            for scheme in ('upspa', 'pastau', 'augsso'):
                add(suite, scheme, n, t)
    for n, t, q in RESILIENCE:
        for scheme in ('upspa', 'roupspa'):
            add('resilience', scheme, n, t, q)
    return jobs


def _number(value, name, line):
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError(f'line {line}: invalid {name}={value!r}') from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f'line {line}: {name} must be finite and nonnegative')
    return parsed


def _int_field(row, name, line):
    try:
        value = int(row[name])
    except (KeyError, ValueError) as exc:
        raise ValueError(f'line {line}: invalid integer {name}') from exc
    if value < 0:
        raise ValueError(f'line {line}: negative {name}')
    return value


def normalize_dat(path, job):
    """Validate one bench_unified DAT and return its rows without fabricating data.

    Raw phase/kind/fields are retained. Paper timings always use p50_ns, never
    total_ns (the unified wrapper fills legacy total_ns from mean_ns). PASTA-U
    provider components are kept separately; there is no fabricated phase total.
    Native AugSSO *_p50sum rows are explicitly sums of calibrated medians, not
    empirical phase distributions. Their p95/mean/stddev are therefore not exposed.
    """
    lines = Path(path).read_text(encoding='utf-8').splitlines()
    if not lines:
        raise ValueError(f'{path}: empty result file')
    header = lines[0].split()
    required = {'scheme', 'phase', 'kind', 'net_profile', 'nsp', 'tsp', 'qsp', 'unavailable',
                'samples', 'warmup', 'p50_ns', 'p95_ns', 'min_ns', 'max_ns', 'mean_ns',
                'stddev_ns', 'result', 'rng_in_timed'}
    if len(set(header)) != len(header) or not required.issubset(header):
        raise ValueError(f'{path}: invalid header or missing columns: {sorted(required-set(header))}')
    scheme = job['scheme']
    modern = scheme in ('upspa', 'roupspa')
    expected_q = job['q'] if scheme == 'roupspa' else job['n'] if scheme == 'upspa' else 0
    expected_offline = job['n']-job['q'] if scheme == 'roupspa' and job['offline'] == 'max' else 0
    native_kinds = {'client', 'provider', 'full_net'} if modern else {'proto', 'sp', 'full'}
    records, seen, covered = [], set(), set()
    raw_components = set()
    for line_number, text in enumerate(lines[1:], 2):
        if not text.strip():
            continue
        values = text.split()
        if len(values) != len(header):
            raise ValueError(f'line {line_number}: row width {len(values)} != header width {len(header)}')
        row = dict(zip(header, values))
        if row['scheme'] != scheme or (_int_field(row, 'nsp', line_number), _int_field(row, 'tsp', line_number)) != (job['n'], job['t']):
            raise ValueError(f'line {line_number}: wrong scheme/coordinate')
        for name, expected in [('qsp', expected_q), ('unavailable', expected_offline),
                               ('samples', job['samples']), ('warmup', job['warmups']), ('rng_in_timed', 0)]:
            if _int_field(row, name, line_number) != expected:
                raise ValueError(f'line {line_number}: {name} must be {expected}, got {row[name]}')
        if row['kind'] not in native_kinds:
            raise ValueError(f'line {line_number}: unexpected kind {row["kind"]}')
        if row['result'] not in ('ok', 'completed'):
            raise ValueError(f'line {line_number}: unsuccessful result {row["result"]}')
        numbers = {key: _number(row[key], key, line_number) for key in
                   ('min_ns', 'p50_ns', 'p95_ns', 'max_ns', 'mean_ns', 'stddev_ns')}
        if not numbers['min_ns'] <= numbers['p50_ns'] <= numbers['p95_ns'] <= numbers['max_ns']:
            raise ValueError(f'line {line_number}: inconsistent quantiles')
        raw_phase, kind, profile = row['phase'], row['kind'], row['net_profile']
        key = (raw_phase, kind, profile)
        if key in seen:
            raise ValueError(f'line {line_number}: duplicate phase/kind/profile {key}')
        seen.add(key)
        phase = raw_phase
        if not modern and kind == 'full':
            if phase.endswith('_lan') or phase.endswith('_wan'):
                phase, suffix = phase.rsplit('_', 1)
                if profile != suffix:
                    raise ValueError(f'line {line_number}: network suffix/profile disagree')
            else:
                raise ValueError(f'line {line_number}: legacy full row lacks LAN/WAN suffix')
        if phase == 'update':
            phase = 'pwdupd'
        panel = {'proto': 'client', 'client': 'client', 'provider': 'provider', 'sp': 'provider_components'}.get(kind, profile)
        if kind in ('full', 'full_net'):
            if profile not in ('lan', 'wan'):
                raise ValueError(f'line {line_number}: full-network row lacks LAN/WAN profile')
        elif profile != 'none':
            raise ValueError(f'line {line_number}: local row has network profile {profile}')
        statistic = 'measured_sample_median'
        components_for = []
        if kind == 'sp':
            raw_components.add(raw_phase)
            components_for = [p for p, names in PROVIDER_COMPONENTS[scheme].items() if raw_phase in names]
            phase = {'reg_store': 'reg', 'auth_total_p50sum': 'auth', 'update_total_p50sum': 'pwdupd'}.get(raw_phase, raw_phase)
            if raw_phase.endswith('_p50sum'):
                statistic = 'sum_of_calibrated_component_medians'
                panel = 'provider'
            elif raw_phase == 'reg_store':
                panel = 'provider' if scheme == 'augsso' else 'provider_components'
        if modern and phase not in job['phases']:
            raise ValueError(f'line {line_number}: unexpected modern phase {phase}')
        if panel != 'provider_components' and phase in job['phases']:
            covered.add((phase, panel))
        record = dict(job_id=job['id'], group=job['group'], suite=job['suite'], scheme=scheme,
                      n=job['n'], t=job['t'], q=expected_q, comparison_q=job['q'],
                      unavailable=expected_offline, phase=phase, panel=panel,
                      raw_phase=raw_phase, raw_kind=kind, net_profile=profile,
                      samples=job['samples'], warmups=job['warmups'],
                      p50_ns=numbers['p50_ns'], p50_ms=numbers['p50_ns']/1e6,
                      statistic=statistic, components_for=components_for,
                      provider_scope=job['provider_panel'] if kind in ('sp', 'provider') else None,
                      measurement_model=job['measurement_model'],
                      selected_for_pdf=(phase in job['phases'] and panel in job['expected'][phase]) or bool(components_for),
                      warnings=list(job['warnings']), raw_fields=row)
        if statistic == 'measured_sample_median':
            record.update({key: numbers[key] for key in ('min_ns', 'p95_ns', 'max_ns', 'mean_ns', 'stddev_ns')})
        records.append(record)
    if not records:
        raise ValueError(f'{path}: header-only result')
    if not modern:
        for phase, components in PROVIDER_COMPONENTS[scheme].items():
            if all(name in raw_components for name in components):
                covered.add((phase, 'provider'))
    missing = [(phase, panel) for phase, panels in job['expected'].items() for panel in panels
               if (phase, panel) not in covered]
    if missing:
        raise ValueError(f'{path}: missing required phase/panel coverage: {missing}')
    return records
