#!/usr/bin/env python3
"""Explicit, reproducible configuration matrix for the RoUpSPA paper runner."""
import argparse
import copy
import json
import os
from pathlib import Path


def q_min(n, t):
    return (n + t - 1) // 2 + 1


def profile(name, delay, jitter=0, bandwidth=1000):
    return dict(name=name, delay_ms=delay, jitter_ms=jitter,
                bandwidth_mbps=bandwidth, loss_percent=0.0)


ZERO = profile('zero', 0)
LAN = profile('lan', .25, .025)
WAN = profile('wan', 30, 2.5, 50)
STANDARD = [ZERO, LAN, WAN]
RTT = [profile('rtt0', 0), profile('rtt10', 5, .5),
       profile('rtt60', 30, 2.5, 50), profile('rtt100', 50, 5, 50)]


def faults(count, action='stop', stage=''):
    return [dict(role='provider', provider_id=i, action=action, stage=stage)
            for i in range(1, count + 1)]


def configuration_matrix(env=None, preflight=False):
    env = os.environ if env is None else env
    def number(name, default):
        value = int(env.get(name, default))
        if value < 0:
            raise ValueError(f'{name} must be nonnegative')
        return value
    delta = number('DELTA_BASE', 100)
    timeout = number('TIMEOUT_BASE', 2500)
    policies = {
        'PERF': (10, 50, 3), 'FAULT': (0, 10, 3),
        'RECOVERY': (0, 10, 3), 'SCALING': (5, 30, 3),
    }
    rows = []
    def add(suite, label, phase, *, n=7, t=3, q=5, command='compare',
            schemes=None, profiles=None, losses=None, fs=None,
            policy='PERF', fanout='all', read_policy='quorum',
            delta_ms=None, timeout_ms=None):
        defaults = policies[policy]
        warmups, samples, repetitions = (
            number(f'{policy}_{key}', default) for key, default in
            zip(('WARMUPS', 'SAMPLES', 'REPS'), defaults))
        if preflight:
            warmups, samples, repetitions = 0, 1, 1
        config = dict(
            n_sp=n, t_sp=t, q_sp=q, phase=phase,
            schemes=schemes or ['roupspa'],
            providers=[f'127.0.0.1:{19000+i}' for i in range(1, n + 1)],
            login_server='127.0.0.1:19100', profiles=copy.deepcopy(profiles or [LAN]),
            loss_levels=losses or [0.0], delta_ms=delta if delta_ms is None else delta_ms,
            timeout_ms=timeout if timeout_ms is None else timeout_ms,
            retry_ms=number('RETRY_BASE', 5), warmups=warmups, samples=samples,
            repetitions=repetitions, connection_policy='fresh_per_request',
            state_dir='network-state', output_dir='', faults=fs or [],
            fanout=fanout, read_policy=read_policy)
        if not (1 <= t <= q <= n and 2*q-n > t-1):
            raise ValueError(f'invalid quorum coordinates for {suite}/{label}')
        if not all(config[k] > 0 for k in ('samples', 'repetitions', 'delta_ms', 'timeout_ms', 'retry_ms')):
            raise ValueError(f'positive sampling/timing values required for {suite}/{label}')
        read_size = t if read_policy == 'threshold' else n - q + t
        warnings = []
        if phase == 'password_update' and read_size < 2*t - 1:
            warnings.append('RoUpSPA has too few replies for unverified new-password consistency; expected clean abort before writing, including without faults. Baseline results remain independent.')
        if fs and any(f['action'] in ('stop', 'restart') for f in fs):
            warnings.append('Post-restart account synchronization remains fail-closed when completion evidence is unavailable; inspect recovery outcomes separately.')
        if read_policy == 'threshold':
            warnings.append('Legacy threshold-read ablation only; completion is not evidence of quorum-read security.')
        rows.append(dict(suite=suite, label=label, command=command, config=config,
                         read_size=read_size, password_consistency_min_replies=2*t-1,
                         warnings=warnings))
    for phase in ('registration', 'authentication', 'secret_update', 'password_update'):
        add('exp01', f'healthy-{phase}', phase, profiles=STANDARD)
    for q in (5, 6, 7):
        for phase in ('secret_update', 'password_update'):
            add('exp02', f'q{q}-{phase}', phase, q=q)
    for t in (2, 3, 5):
        add('exp03', f't{t}-authentication', 'authentication', t=t, q=6)
    for n, t, q in ((4, 2, 3), (7, 3, 5), (10, 5, 8)):
        for phase in ('authentication', 'secret_update'):
            add('exp04', f'n{n}-t{t}-q{q}-{phase}', phase, n=n, t=t, q=q)
    for phase in ('authentication', 'secret_update'):
        add('exp05', f'rtt-sweep-{phase}', phase, profiles=RTT)
        add('exp06', f'loss-{phase}', phase, profiles=[WAN], losses=[0.0, 1.0, 5.0],
            timeout_ms=number('LOSS_TIMEOUT', 4000))
    for count in (0, 1, 2, 3):
        for phase in ('secret_update', 'password_update'):
            add('exp07', f'f{count}-{phase}', phase, command='fault',
                fs=faults(count), policy='FAULT')
    for count in (0, 2, 3, 4, 5):
        add('exp08', f'f{count}-authentication', 'authentication', command='fault',
            fs=faults(count), policy='FAULT')
    for wait in (20, 50, 100, 250):
        for phase in ('secret_update', 'password_update'):
            add('exp09', f'delta{wait}-{phase}', phase, profiles=[ZERO], delta_ms=wait)
    add('exp10', 'missing-login-store', 'registration', command='fault',
        fs=[dict(role='login', provider_id=0, action='suppress', stage='ls_store')],
        policy='RECOVERY', timeout_ms=3000)
    add('exp10', 'client-crash-after-provider-write', 'registration', command='fault',
        fs=[dict(role='client', provider_id=0, action='crash_after', stage='provider_write')],
        policy='RECOVERY', timeout_ms=3000)
    add('exp11', 'provider-stop-return', 'authentication', command='fault',
        fs=faults(1), policy='RECOVERY', timeout_ms=3000)
    add('exp11', 'explicit-synchronization', 'synchronization', policy='RECOVERY', timeout_ms=4000)
    for count in (1, 2, 3):
        add('exp12', f'f{count}-id-write-suppressed', 'password_update', command='fault',
            fs=faults(count, 'suppress', 'id_write'), policy='FAULT')
    for count in (0, 1, 2):
        for phase in ('authentication', 'password_update'):
            for fanout in ('all', 'minimal'):
                add('exp13', f'f{count}-{phase}-{fanout}', phase, command='fault',
                    fs=faults(count, 'corrupt_partial'), policy='FAULT', fanout=fanout)
    for fanout in ('all', 'minimal'):
        for phase in ('setup', 'registration', 'authentication', 'secret_update', 'password_update'):
            add('exp14', f'{fanout}-{phase}', phase, fanout=fanout, profiles=[LAN, WAN])
    for read_policy in ('threshold', 'quorum'):
        for count in (0, 2, 3, 4):
            for phase in ('authentication', 'password_update'):
                add('exp15', f'{read_policy}-f{count}-{phase}', phase, command='fault',
                    fs=faults(count), policy='FAULT', read_policy=read_policy)
    for suite, coords, policy, limit in (
        ('cmp-diagnostic', ((3, 2), (7, 2), (7, 5), (7, 7)), 'PERF', number('COMPARE_TIMEOUT', 5000)),
        ('cmp-scaling', ((10, 6), (20, 12), (30, 18), (40, 24), (50, 30)), 'SCALING', number('SCALING_TIMEOUT', 10000)),
        # A separate lower-threshold grid permits the current unverified
        # new-password check (r >= 2t-1). Do not relabel the original 60% grid.
        ('cmp-supported', tuple((n, (n + 2) // 3) for n in (10, 20, 30, 40, 50)),
         'SCALING', number('SCALING_TIMEOUT', 10000)),
    ):
        for n, t in coords:
            for phase in ('setup', 'authentication', 'password_update'):
                add(suite, f'n{n}-t{t}-{phase}-minimal', phase, n=n, t=t, q=q_min(n,t),
                    schemes=['roupspa', 'pastau', 'augsso'], profiles=[LAN, WAN],
                    fanout='minimal', policy=policy, timeout_ms=limit)
                add(suite, f'n{n}-t{t}-{phase}-roupspa-all', phase, n=n, t=t, q=q_min(n,t),
                    profiles=[LAN, WAN], fanout='all', policy=policy, timeout_ms=limit)
    return rows


def selected_matrix(mode='all', env=None, preflight=False):
    minor_suites = {'exp01', 'exp05', 'exp06', 'exp07', 'exp08', 'exp10',
                    'exp11', 'exp12', 'exp13', 'exp14', 'cmp-supported'}
    selectors = {
        'all': lambda suite: True,
        'paper-minor': lambda suite: suite in minor_suites,
        'roupspa': lambda suite: suite.startswith('exp'),
        'compare-all': lambda suite: suite.startswith('cmp-'),
        'compare-diagnostic': lambda suite: suite == 'cmp-diagnostic',
        'compare-scaling': lambda suite: suite == 'cmp-scaling',
        'compare-supported': lambda suite: suite == 'cmp-supported',
    }
    if mode in {f'exp{i:02}' for i in range(1, 16)}:
        selector = lambda suite: suite == mode
    elif mode in selectors:
        selector = selectors[mode]
    else:
        raise ValueError(f'unknown mode {mode!r}; expected all, paper-minor, roupspa, exp01..exp15, compare-diagnostic, compare-scaling, compare-supported, compare-all')
    return [r for r in configuration_matrix(env, preflight) if selector(r['suite'])]


def write_matrix(output, mode='all', preflight=False, env=None):
    output = Path(output).resolve()
    configs = output / 'configs'
    configs.mkdir(parents=True, exist_ok=True)
    rows = selected_matrix(mode, env, preflight)
    for row in rows:
        slug = row['suite'] + '-' + row['label']
        row['config']['output_dir'] = str(output / '.scratch' / row['suite'] / row['label'])
        row['config_file'] = str(configs / f'{slug}.json')
        row['raw_dir'] = str(output / 'raw' / row['suite'] / row['label'])
        Path(row['config_file']).write_text(json.dumps(row['config'], indent=2) + '\n')
    plan = dict(schema_version=2, mode=mode, preflight=preflight, configs=rows)
    (output / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    return plan


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', nargs='?', default='all')
    parser.add_argument('--output', required=True)
    parser.add_argument('--preflight', action='store_true')
    args = parser.parse_args()
    plan = write_matrix(args.output, args.mode, args.preflight)
    print(f"Generated {len(plan['configs'])} configurations in {args.output}")
