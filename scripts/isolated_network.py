#!/usr/bin/env python3
"""Create a private /run/netns only inside already-isolated namespaces.

Invoke through measurement_process.make_isolated_command; never directly.
The separate mount namespace hides all named child namespaces from the host.
The outer network namespace contains bridges/veths, so terminating the entire
job process group releases resources even before the Rust snapshot is saved.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid


def require_isolated(host_mount_id, host_net_id):
    actual = {name: os.readlink('/proc/self/ns/' + name) for name in ('mnt', 'net')}
    if actual['mnt'] == host_mount_id or actual['net'] == host_net_id:
        raise RuntimeError('refusing to mount: both mount and network namespaces must differ from the caller')
    return actual


def run_probe():
    name = 'measurement-probe-' + uuid.uuid4().hex[:10]
    evidence = []
    created = False
    try:
        for command in (
            ['ip', 'netns', 'add', name],
            ['ip', '-n', name, 'link', 'set', 'lo', 'up'],
            ['ip', 'netns', 'exec', name, 'tc', 'qdisc', 'add', 'dev', 'lo', 'root', 'netem', 'delay', '0ms'],
        ):
            result = subprocess.run(command, text=True, capture_output=True, timeout=20, stdin=subprocess.DEVNULL)
            evidence.append(dict(command=command, rc=result.returncode,
                                 stdout=result.stdout, stderr=result.stderr))
            if result.returncode:
                raise RuntimeError('isolated network probe failed: ' + result.stderr.strip())
            created = True
    finally:
        if created:
            command = ['ip', 'netns', 'del', name]
            result = subprocess.run(command, text=True, capture_output=True, timeout=20, stdin=subprocess.DEVNULL)
            evidence.append(dict(command=command, rc=result.returncode,
                                 stdout=result.stdout, stderr=result.stderr))
        print(json.dumps(evidence, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-mount-id', required=True)
    parser.add_argument('--host-net-id', required=True)
    parser.add_argument('--probe', action='store_true')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    require_isolated(args.host_mount_id, args.host_net_id)
    for name in ('mount', 'ip', 'tc'):
        if shutil.which(name) is None:
            raise RuntimeError('missing required executable: ' + name)
    path = Path('/run/netns')
    if path.is_symlink():
        raise RuntimeError('refusing a symlink at /run/netns')
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755,nosuid,nodev',
                    'measurement-netns', str(path)], check=True, timeout=20,
                   stdin=subprocess.DEVNULL)
    if args.probe:
        if args.command:
            raise ValueError('--probe cannot be combined with a command')
        run_probe()
        return 0
    command = args.command
    if command and command[0] == '--':
        command = command[1:]
    if not command:
        raise ValueError('missing benchmark command')
    os.execvpe(command[0], command, os.environ.copy())


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print('isolated network: ' + str(error), file=sys.stderr)
        sys.exit(1)
