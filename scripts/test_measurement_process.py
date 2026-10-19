#!/usr/bin/env python3
"""Focused tests for unattended subprocess ownership and timeout cleanup."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from isolated_network import require_isolated
from measurement_process import run_logged


def alive(pid):
    try:
        # Zombies cannot run or retain namespaces; some CI PID 1s reap slowly.
        return Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1].split()[0] != 'Z'
    except FileNotFoundError:
        return False


@unittest.skipUnless(sys.platform == 'linux', 'Linux process ownership tests')
class ProcessTests(unittest.TestCase):
    def test_success_and_noninteractive_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_logged([sys.executable, '-c',
                'import sys; print("ok"); print("detail",file=sys.stderr); assert sys.stdin.read()==""'],
                directory, Path(directory) / 'logs', 5)
            self.assertEqual(result['rc'], 0)
            self.assertFalse(result['timed_out'])
            self.assertEqual((Path(directory) / 'logs/stdout.log').read_text(), 'ok\n')
            self.assertEqual((Path(directory) / 'logs/stderr.log').read_text(), 'detail\n')

    def test_timeout_kills_term_ignoring_descendant_after_leader_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / 'descendant.pid'
            script = '''import subprocess,sys,time
child=subprocess.Popen([sys.executable,'-c',
    'import signal,time,sys; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path(sys.argv[1]).write_text(Path("/proc/self/stat").read_text().split()[0]); time.sleep(120)',sys.argv[1]])
time.sleep(120)
'''
            result = run_logged([sys.executable, '-c', script, str(pidfile)],
                                directory, Path(directory) / 'logs', 0.5)
            self.assertTrue(result['timed_out'])
            self.assertNotEqual(result['rc'], 0)
            child_pid = int(pidfile.read_text())
            deadline = time.monotonic() + 2
            while alive(child_pid) and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertFalse(alive(child_pid), f'job descendant {child_pid} survived')

    def test_natural_leader_exit_does_not_leave_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / 'descendant.pid'
            script = '''import subprocess,sys,time
from pathlib import Path
child=subprocess.Popen([sys.executable,'-c',
    'import time,sys; from pathlib import Path; Path(sys.argv[1]).write_text(Path("/proc/self/stat").read_text().split()[0]); time.sleep(120)',sys.argv[1]])
while not Path(sys.argv[1]).exists(): time.sleep(.01)
'''
            result = run_logged([sys.executable, '-c', script, str(pidfile)],
                                directory, Path(directory) / 'logs', 5)
            self.assertEqual(result['rc'], 0)
            self.assertFalse(result['timed_out'])
            self.assertFalse(alive(int(pidfile.read_text())))

    def test_direct_isolation_invocation_refused(self):
        with self.assertRaises(RuntimeError):
            require_isolated(os.readlink('/proc/self/ns/mnt'), os.readlink('/proc/self/ns/net'))

    def test_one_namespace_change_is_insufficient(self):
        with patch('isolated_network.os.readlink', side_effect=['mnt:new', 'net:old']):
            with self.assertRaises(RuntimeError):
                require_isolated('mnt:old', 'net:old')


if __name__ == '__main__':
    unittest.main()
