#!/usr/bin/env python3
"""Focused tests for configuration validity and statistically honest summaries."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import subprocess

import paper_runner

from paper_configs import q_min, selected_matrix, write_matrix
from summarize_raw import population, summarize_file, summarize_tree


class ConfigurationTests(unittest.TestCase):
    def test_all_coordinates_and_comparison_semantics(self):
        rows = selected_matrix(env={})
        names = [(r['suite'], r['label']) for r in rows]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue({f'exp{i:02}' for i in range(1, 16)} <= {r['suite'] for r in rows})
        for row in rows:
            c = row['config']
            self.assertTrue(1 <= c['t_sp'] <= c['q_sp'] <= c['n_sp'])
            self.assertGreater(2*c['q_sp'] - c['n_sp'], c['t_sp'] - 1)
            self.assertNotIn('upspa', c['schemes'])
            if row['suite'].startswith('cmp-'):
                self.assertEqual(c['q_sp'], q_min(c['n_sp'], c['t_sp']))
                self.assertIn(c['phase'], ('setup', 'authentication', 'password_update'))
                if c['fanout'] == 'minimal':
                    self.assertEqual(c['schemes'], ['roupspa', 'pastau', 'augsso'])
                else:
                    self.assertEqual(c['schemes'], ['roupspa'])
    def test_preflight_keeps_every_config_and_profile(self):
        regular = selected_matrix(env={})
        preflight = selected_matrix(env={}, preflight=True)
        self.assertEqual(len(regular), len(preflight))
        for regular_row, row in zip(regular, preflight):
            c = row['config']
            self.assertEqual((c['warmups'], c['samples'], c['repetitions']), (0, 1, 1))
            self.assertEqual(c['profiles'], regular_row['config']['profiles'])
            self.assertEqual(c['loss_levels'], regular_row['config']['loss_levels'])
    def test_unsupported_new_password_has_explicit_warning(self):
        rows = selected_matrix('compare-diagnostic', env={})
        blocked = [r for r in rows if r['config']['phase'] == 'password_update'
                   and r['read_size'] < r['password_consistency_min_replies']]
        self.assertTrue(blocked)
        self.assertTrue(all(any('expected clean abort' in w for w in r['warnings']) for r in blocked))
    def test_fault_suites_reach_intended_stage(self):
        rows = selected_matrix('exp12', env={})
        self.assertEqual([len(r['config']['faults']) for r in rows], [1,2,3])
        self.assertTrue(all(f['stage'] == 'id_write' and f['action'] == 'suppress'
                            for r in rows for f in r['config']['faults']))
        self.assertEqual(len(selected_matrix('exp13', env={})), 12)
        self.assertEqual(len(selected_matrix('exp15', env={})), 16)
    def test_supported_grid_meets_password_consistency_and_fault_bounds(self):
        rows = selected_matrix('compare-supported', env={})
        coordinates = {(r['config']['n_sp'], r['config']['t_sp'], r['config']['q_sp'])
                       for r in rows}
        self.assertEqual(coordinates, {(10,4,7), (20,7,14), (30,10,20),
                                       (40,14,27), (50,17,34)})
        self.assertEqual(len(rows), 30)
        for row in rows:
            c = row['config']
            self.assertGreaterEqual(row['read_size'], 2*c['t_sp'] - 1)
            self.assertLessEqual(c['q_sp'], c['n_sp'] - c['t_sp'] + 1)
            self.assertLess(c['q_sp'], c['n_sp'])
            self.assertFalse(row['warnings'])
        # The 60% comparison remains a distinct diagnostic, including aborts.
        legacy_updates = [r for r in selected_matrix('compare-scaling', env={})
                          if r['config']['phase'] == 'password_update']
        self.assertEqual(len(legacy_updates), 10)
        self.assertTrue(all(r['read_size'] < r['password_consistency_min_replies']
                            and r['warnings'] for r in legacy_updates))
    def test_minor_plan_preserves_fault_cases_without_unsupported_grid(self):
        rows = selected_matrix('paper-minor', env={})
        self.assertEqual({r['suite'] for r in rows},
                         {'exp01','exp05','exp06','exp07','exp08','exp10',
                          'exp11','exp12','exp13','exp14','cmp-supported'})
        self.assertTrue(all(r['read_size'] >= r['password_consistency_min_replies']
                            for r in rows if r['config']['phase'] == 'password_update'))
        self.assertTrue(any(r['config']['faults'] for r in rows))


def record(outcome='completed', duration=100, **extra):
    result = dict(scheme='roupspa', phase='authentication', session='s', outcome=outcome,
                  reason=None, metrics=dict(end_to_end_ns=duration, terminal_ns=20,
                                           drain_ns=10, client_ns=50, discards=0),
                  client_measurement_unavailable=False)
    row = dict(result=result, run_id='trial', profile='lan', loss_percent=0,
               repetition=0, sample=0, warmup=False, fixture=False,
               provider_handler_ns=5, login_handler_ns=2, process_wall_ns=duration+5)
    row.update(extra)
    return row


class SummaryTests(unittest.TestCase):
    def test_outcome_denominators_missing_metrics_and_populations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'raw.jsonl'
            complete = record()
            aborted = record('cleanly_aborted', 200)
            crashed = record('unresolved', 300)
            crashed['result']['client_measurement_unavailable'] = True
            blocked = record('failed', 0)
            blocked['result']['session'] = 'fixture-blocked'
            recovery = record(run_id='trial-after-restart', fixture=True)
            fixture = record(fixture=True)
            warmup = record(warmup=True)
            path.write_text('\n'.join(json.dumps(r) for r in
                                      (complete, aborted, crashed, blocked, recovery, fixture, warmup)))
            summary = summarize_file(path, 'exp08', 'test')
            groups = {g['population']: g for g in summary['groups']}
            measured = groups['measured']
            self.assertEqual(measured['attempts'], 4)
            self.assertEqual(measured['success_rate'], .25)
            self.assertEqual(measured['outcomes']['cleanly_aborted'], 1)
            end = measured['timings']['end_to_end_ns']['all_attempts']
            self.assertEqual((end['samples'], end['missing'], end['p50'], end['p95'], end['mean'], end['sd']),
                             (3, 1, 200, 300, 200, 100))
            client = measured['timings']['client_ns']['all_attempts']
            self.assertEqual((client['samples'], client['missing']), (2, 2))
            self.assertEqual(measured['timings']['end_to_end_excl_terminal_wait_ns']['all_attempts']['mean'], 130)
            self.assertEqual(measured['timings']['end_to_end_excl_drain_ns']['completed']['mean'], 90)
            self.assertIsNone(measured['counters']['toprf_subsets_tried']['all_attempts']['mean'])
            self.assertEqual(groups['recovery']['attempts'], 1)
            self.assertEqual(groups['fixture']['attempts'], 1)
            self.assertEqual(groups['warmup_measured']['attempts'], 1)
            self.assertEqual(groups['recovery']['handler_scope'], 'cumulative_snapshot')
    def test_explicit_synchronization_is_measured_not_recovery(self):
        row = record()
        row['result']['phase'] = 'synchronization'
        row['result']['metrics']['repair_ns'] = 42
        self.assertEqual(population(row), 'measured')
        row['fixture'] = True
        self.assertEqual(population(row), 'recovery')
    def test_missing_config_visible_in_availability(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            plan = write_matrix(output, 'exp12', True, env={})
            analysis = summarize_tree(output)
            index = json.loads((analysis / 'index.json').read_text())
            self.assertEqual(len(index['configurations']), 3)
            self.assertTrue(all(r['availability'][0]['evidence_status'] == 'missing'
                                for r in index['configurations']))
            self.assertTrue((analysis / 'availability.csv').exists())
    def test_malformed_evidence_is_not_silently_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'raw.jsonl'
            path.write_text('{truncated')
            with self.assertRaisesRegex(ValueError, 'invalid raw record'):
                summarize_file(path, 'x', 'y')


class BuildProvenanceTests(unittest.TestCase):
    def test_failed_build_never_falls_back_to_shipped_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shipped = root / 'binaries/linux-x86_64/bench_network'
            shipped.parent.mkdir(parents=True)
            shipped.write_text('stale binary')
            output = root / 'out'
            output.mkdir()
            with mock.patch.dict('os.environ', {}, clear=True), \
                 mock.patch('paper_runner.shutil.which', return_value='/usr/bin/cargo'), \
                 mock.patch('paper_runner.subprocess.run', return_value=subprocess.CompletedProcess([], 1, '', 'build failed')) as run, \
                 mock.patch('paper_runner.subprocess.check_output') as probe:
                with self.assertRaisesRegex(RuntimeError, 'cargo build failed'):
                    paper_runner.build(root, output)
                self.assertEqual(run.call_args.args[0][:4], ['cargo', 'build', '--locked', '--release'])
                probe.assert_not_called()
    def test_stale_capability_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'bench_network'
            binary.write_bytes(b'fixture')
            output = root / 'out'
            output.mkdir()
            artifact = json.dumps(dict(reason='compiler-artifact', target={'name':'bench_network'}, executable=str(binary)))
            with mock.patch.dict('os.environ', {}, clear=True), \
                 mock.patch('paper_runner.shutil.which', return_value='/usr/bin/cargo'), \
                 mock.patch('paper_runner.subprocess.run', return_value=subprocess.CompletedProcess([], 0, artifact, '')), \
                 mock.patch('paper_runner.subprocess.check_output', return_value='{"capabilities_version":1}'):
                with self.assertRaisesRegex(RuntimeError, 'capabilities_version'):
                    paper_runner.build(root, output)


if __name__ == '__main__':
    unittest.main()
