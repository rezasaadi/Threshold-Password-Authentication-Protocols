#!/usr/bin/env python3
"""Bounded, logged subprocesses and private network-harness invocations."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


def _signal_group(pgid, sig):
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        pass


def _group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def _stop_group(proc):
    """Reap the leader and kill descendants even if the leader already exited."""
    _signal_group(proc.pid, signal.SIGTERM)
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        proc.poll()
        if not _group_exists(proc.pid):
            break
        time.sleep(0.05)
    # A leader can exit on TERM while descendants ignore it. Always address
    # the original, isolated process group rather than only the leader PID.
    _signal_group(proc.pid, signal.SIGKILL)
    proc.wait()


def run_logged(command, cwd, logdir, timeout, env=None):
    """Run one job; retain logs and return rc/timed_out/elapsed/command.

    All descendants must retain the process group (as the Rust
    harness does). A job cannot read a terminal or request interactive input.
    KeyboardInterrupt and other interruptions clean the group before raising.
    """
    if timeout <= 0:
        raise ValueError('timeout must be positive')
    command = [os.fspath(arg) for arg in command]
    logdir = Path(logdir)
    logdir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    timed_out = False
    with (logdir / 'stdout.log').open('wb') as stdout, (logdir / 'stderr.log').open('wb') as stderr:
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _stop_group(proc)
        except BaseException:
            _stop_group(proc)
            raise
        finally:
            # Do not leave children after a leader exits on its own either.
            if _group_exists(proc.pid):
                _stop_group(proc)
    return dict(rc=proc.returncode, timed_out=timed_out,
                elapsed=time.monotonic() - started, command=command)


def check_isolation_tools():
    """Return required executables or raise; never install or invoke sudo."""
    found = {name: shutil.which(name) for name in ('unshare', 'mount', 'ip', 'tc')}
    missing = [name for name, executable in found.items() if executable is None]
    if missing:
        raise RuntimeError('private network runs require: ' + ', '.join(missing))
    if sys.platform != 'linux':
        raise RuntimeError('private network runs require Linux')
    return found


def make_isolated_command(command):
    """Wrap a command in new mount/network namespaces and a private netns dir."""
    required = check_isolation_tools()
    command = [os.fspath(arg) for arg in command]
    if not command:
        raise ValueError('isolated command cannot be empty')
    return [required['unshare'], '--mount', '--net', '--propagation', 'private', '--',
            sys.executable, str(Path(__file__).resolve().with_name('isolated_network.py')),
            '--host-mount-id', os.readlink('/proc/self/ns/mnt'),
            '--host-net-id', os.readlink('/proc/self/ns/net'), '--', *command]


def make_isolation_probe_command():
    """Use the same isolation setup for the preflight namespace/tc probe."""
    command = make_isolated_command(['--probe'])
    # --probe belongs to isolated_network.py, rather than an executable.
    command[-2:] = ['--probe']
    return command
