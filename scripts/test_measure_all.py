#!/usr/bin/env python3
"""Evidence acceptance and unattended status tests; no benchmark timings."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import measure_all as master


class EvidenceTests(unittest.TestCase):
    def fixture(self, directory, outcome='completed'):
        stage = Path(directory) / 'full'
        job = copy.deepcopy(master.make_plan({})['jobs'][0])
        job['config'].update(warmups=0, samples=1, repetitions=1,
                             profiles=[job['config']['profiles'][0]])
        master.prepare_network(stage, job)
        config = master.read(stage / 'config.json')
        run = stage / 'native/run-test'
        run.mkdir(parents=True)
        for name in ('environment.json', 'summary.json', 'session-outcomes.json'):
            master.save(run / name, {})
        master.save(run / 'requested-config.json', config)
        record = dict(result=dict(scheme='roupspa', phase=config['phase'],
                      outcome=outcome, metrics={}, session='fixture-blocked' if outcome == 'failed' else 'session'),
                      profile=config['profiles'][0]['name'], loss_percent=0.0,
                      repetition=0, sample=0, warmup=False, fixture=False,
                      run_id='run-sample0', process_wall_ns=123,
                      provider_handler_ns=2, login_handler_ns=3)
        (run / 'raw.jsonl').write_text(json.dumps(record) + '\n')
        return stage, job, run, record

    def test_all_native_outcomes_are_evidence_not_runner_errors(self):
        for outcome in ('completed', 'cleanly_aborted', 'unresolved', 'failed'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                stage, job, _, _ = self.fixture(directory, outcome)
                result = master.verify_network(stage, job)
                self.assertEqual(result['availability'][0]['evidence_status'], 'complete')
                self.assertEqual(result['availability'][0]['completed'], int(outcome == 'completed'))

    def test_duplicate_and_missing_measured_rows_rejected(self):
        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                stage, job, run, record = self.fixture(directory)
                (run / 'raw.jsonl').write_text('' if missing else (json.dumps(record) + '\n') * 2)
                with self.assertRaisesRegex(ValueError, 'coverage mismatch'):
                    master.verify_network(stage, job)

    def test_wrong_native_config_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            stage, job, run, _ = self.fixture(directory)
            config = master.read(run / 'requested-config.json')
            config['fanout'] = 'minimal'
            master.save(run / 'requested-config.json', config)
            with self.assertRaisesRegex(ValueError, 'differs from submitted'):
                master.verify_network(stage, job)

    def test_recovery_row_cannot_replace_primary_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            stage, job, run, record = self.fixture(directory)
            record.update(run_id='run-sample0-after-restart', fixture=True)
            (run / 'raw.jsonl').write_text(json.dumps(record) + '\n')
            with self.assertRaisesRegex(ValueError, 'coverage mismatch'):
                master.verify_network(stage, job)


class StatusTests(unittest.TestCase):
    def test_lock_contention_marks_new_run_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            master.save(output / 'progress.json', dict(status='QUEUED', jobs=[]))
            master.record_lock_contention(output)
            self.assertEqual(master.read(output / 'progress.json')['status'], 'BLOCKED')
            self.assertIn('Another measurement worker', master.read(output / 'FINAL_STATUS.json')['error'])

    def test_lock_contention_preserves_active_worker_progress(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            state = dict(status='RUNNING', pid=1234, jobs=[])
            master.save(output / 'progress.json', state)
            master.record_lock_contention(output)
            self.assertEqual(master.read(output / 'progress.json'), state)
            self.assertFalse((output / 'FINAL_STATUS.json').exists())

    def test_plan_has_exact_groups_and_all_15_experiments(self):
        jobs = master.make_plan({})['jobs']
        network = [job for job in jobs if job['engine'] == 'network']
        self.assertEqual(len(network), 89)
        self.assertEqual({job['suite'] for job in network}, {f'exp{i:02}' for i in range(1, 16)})
        self.assertEqual({job['group'] for job in jobs},
                         {'roupspa_exp01_exp15', 'upspa_vs_roupspa', 'upspa_vs_pastau_vs_augsso'})


class WorkerFlowTests(unittest.TestCase):
    def test_failure_continues_and_resume_skips_verified_complete_job(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            plan = master.make_plan({})
            plan['jobs'] = [j for j in plan['jobs'] if j['engine'] == 'pdf'][:2]
            master.save(output / 'plan.json', plan)
            master.save(output / 'plan-sha256.json', master.digest(output / 'plan.json'))
            master.save(output / 'source-sha256.json', {})
            master.save(output / 'progress.json', dict(status='QUEUED', jobs=[
                dict(id=j['id'], group=j['group'], status='pending', attempt=0, stage=None, error=None)
                for j in plan['jobs']]))
            binary = output / 'synthetic-executable'
            binary.write_bytes(b'unit-test-only; never executed')
            actual = []
            fail_first = True

            def synthetic_stage(stage, job, binaries, timeout, validate=False):
                if validate:
                    return
                actual.append(job['id'])
                if fail_first and job['id'] == plan['jobs'][0]['id']:
                    raise RuntimeError('synthetic timeout')
                stage.mkdir(parents=True, exist_ok=True)
                master.save(stage / 'normalized.json', [])

            with patch.object(master, 'source_hashes', return_value={}), \
                 patch.object(master, 'checked'), \
                 patch.object(master, 'build', return_value={'bench_network': str(binary), 'bench_unified': str(binary)}), \
                 patch.object(master, 'make_isolation_probe_command', return_value=['synthetic-probe']), \
                 patch.object(master.shutil, 'which', return_value='/unused'), \
                 patch.object(master.signal, 'signal'), \
                 patch.object(master, 'run_stage', side_effect=synthetic_stage), \
                 patch.object(master, 'verify', return_value=[]):
                self.assertEqual(master.worker(output, output / 'worker.lock'), 1)
                state = master.read(output / 'FINAL_STATUS.json')
                self.assertEqual([j['status'] for j in state['jobs']], ['failed', 'complete'])
                fail_first = False
                self.assertEqual(master.worker(output, output / 'worker.lock'), 0)
                self.assertEqual(actual, [plan['jobs'][0]['id'], plan['jobs'][1]['id'], plan['jobs'][0]['id']])
                state = master.read(output / 'FINAL_STATUS.json')
                self.assertEqual([j['attempt'] for j in state['jobs']], [2, 1])
                self.assertEqual(state['status'], 'COMPLETE')

    def test_changed_plan_blocks_before_any_build(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            master.save(output / 'plan.json', {'jobs': []})
            master.save(output / 'plan-sha256.json', 'incorrect')
            master.save(output / 'progress.json', dict(status='QUEUED', jobs=[]))
            with patch.object(master.signal, 'signal'), patch.object(master, 'build') as build:
                self.assertEqual(master.worker(output, output / 'worker.lock'), 1)
                build.assert_not_called()
            self.assertEqual(master.read(output / 'FINAL_STATUS.json')['status'], 'BLOCKED')


if __name__ == '__main__':
    unittest.main()
