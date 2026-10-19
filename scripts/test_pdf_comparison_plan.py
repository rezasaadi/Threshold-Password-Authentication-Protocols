import copy
import tempfile
import unittest
from pathlib import Path

from pdf_comparison_plan import (DEPLOYMENT, FIXED_THRESHOLD, PROPORTIONAL, RESILIENCE,
                                 comparison_jobs, normalize_dat)

# Exact 33-column OUTPUT_COLUMNS emitted by src/bin/bench_unified.rs.
HEADER = ('scheme phase kind net_profile nsp tsp qsp unavailable delivery_bound_ns samples warmup '
          'client_ns provider_ns login_server_ns network_ns total_ns identification_stage_ns '
          'account_read_stage_ns prepare_stage_ns write_stage_ns terminal_stage_ns request_bytes '
          'response_bytes message_count acknowledgement_count result rng_in_timed min_ns p50_ns '
          'p95_ns max_ns mean_ns stddev_ns').split()


def fixture_rows(job):
    scheme = job['scheme']
    specs = []
    if scheme in ('upspa', 'roupspa'):
        for phase in job['phases']:
            specs.extend([(phase, 'client', 'none'), (phase, 'provider', 'none'),
                          (phase, 'full_net', 'lan'), (phase, 'full_net', 'wan')])
    else:
        specs.extend((phase, 'proto', 'none') for phase in ('setup', 'reg', 'auth', 'update'))
        components = ('reg_store', 'auth_db_get', 'auth_respond', 'update_respond', 'update_handle') if scheme == 'pastau' else (
            'reg_store', 'auth_db_get', 'auth_respond1', 'auth_respond2', 'update_respond1', 'update_respond2',
            'auth_total_p50sum', 'update_total_p50sum')
        specs.extend((phase, 'sp', 'none') for phase in components)
        specs.extend((phase + '_' + net, 'full', net) for phase in ('reg', 'auth', 'update') for net in ('lan', 'wan'))
    rows = []
    for phase, kind, profile in specs:
        row = dict.fromkeys(HEADER, 0)
        row.update(dict(scheme=scheme, phase=phase, kind=kind, net_profile=profile,
                         nsp=job['n'], tsp=job['t'], qsp=job['q'] if scheme == 'roupspa' else job['n'] if scheme == 'upspa' else 0,
                         unavailable=job['n']-job['q'] if scheme == 'roupspa' and job['offline'] == 'max' else 0,
                         samples=job['samples'], warmup=job['warmups'], min_ns=100, p50_ns=200, p95_ns=300,
                         max_ns=400, mean_ns=250, stddev_ns=40, total_ns=250, result='completed' if scheme in ('upspa', 'roupspa') else 'ok', rng_in_timed=0))
        rows.append(row)
    return rows


class PdfComparisonPlanTests(unittest.TestCase):
    def setUp(self):
        self.jobs = comparison_jobs(env={})
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'raw.dat'

    def write(self, rows):
        self.path.write_text(' '.join(HEADER) + '\n' + '\n'.join(' '.join(str(r[k]) for k in HEADER) for r in rows) + '\n')

    def test_exact_pdf_grids_groups_and_counts(self):
        self.assertEqual(len(self.jobs), 91)
        self.assertEqual(len({j['id'] for j in self.jobs}), 91)
        for suite, grid in [('deployment', DEPLOYMENT), ('fixed_threshold', FIXED_THRESHOLD), ('proportional', PROPORTIONAL)]:
            actual = [j for j in self.jobs if j['suite'] == suite]
            self.assertEqual(len(actual), len(grid)*3)
            self.assertEqual({(j['n'], j['t']) for j in actual}, set(grid))
            self.assertEqual({j['scheme'] for j in actual}, {'upspa', 'pastau', 'augsso'})
        resilient = [j for j in self.jobs if j['suite'] == 'resilience']
        self.assertEqual({(j['n'], j['t'], j['q']) for j in resilient}, set(RESILIENCE))
        self.assertEqual({j['scheme'] for j in resilient}, {'upspa', 'roupspa'})
        self.assertEqual(PROPORTIONAL[-1], (100, 60))

    def test_flags_match_engine_interfaces_and_timing(self):
        for job in self.jobs:
            flags = dict(zip(job['flags'][::2], job['flags'][1::2]))
            self.assertEqual(flags['--sample-size'], '200')
            self.assertEqual(flags['--warmup-iters'], '50')
            self.assertEqual(flags['--proc-samples'], '200')
            self.assertEqual(flags['--proc-warmup'], '50')
            self.assertEqual(flags['--lan-rtt-ms'], '0.5')
            self.assertEqual(flags['--wan-rtt-ms'], '60')
            self.assertNotIn('--out', flags)
            self.assertNotIn('--rng-in-timed', flags)
            if job['scheme'] == 'roupspa':
                self.assertEqual(flags['--offline'], 'max')
                self.assertEqual(job['phases'], ['reg', 'secupd', 'pwdupd'])
                self.assertTrue(job['warnings'])
            else:
                self.assertNotIn('--offline', flags)

    def test_preflight_is_one_sample_and_environment_overrides_are_recorded(self):
        jobs = comparison_jobs(True, {'PDF_SAMPLES': '7', 'PDF_WARMUPS': '2', 'PDF_OFFLINE': 'none'})
        self.assertTrue(all((j['samples'], j['warmups'], j['proc_samples'], j['proc_warmups']) == (1, 0, 1, 0) for j in jobs))
        self.assertTrue(all(j['offline'] == 'none' for j in jobs))
        job = comparison_jobs(env={'PDF_SAMPLES': '7', 'PDF_WARMUPS': '2'})[0]
        self.assertEqual((job['samples'], job['warmups']), (7, 2))
        for env in ({'PDF_SAMPLES': '0'}, {'PDF_WARMUPS': '-1'}, {'PDF_OFFLINE': '1'}):
            with self.assertRaises(ValueError):
                comparison_jobs(env=env)

    def test_every_job_accepts_native_complete_fixture(self):
        for job in self.jobs:
            with self.subTest(job=job['id']):
                rows = fixture_rows(job)
                self.write(rows)
                records = normalize_dat(self.path, job)
                self.assertEqual(len(records), len(rows))
                self.assertTrue(all(r['p50_ns'] == 200 for r in records))
                self.assertTrue(all(r['p50_ms'] == 0.0002 for r in records))
                self.assertTrue(all(r['raw_fields']['total_ns'] == '250' for r in records))

    def test_provider_outputs_use_main_counts_not_internal_full_network_calibration(self):
        jobs = comparison_jobs(env={'PDF_SAMPLES': '3', 'PDF_WARMUPS': '2',
                                    'PDF_PROC_SAMPLES': '11', 'PDF_PROC_WARMUPS': '7'})
        for scheme in ('pastau', 'augsso'):
            job = next(j for j in jobs if j['scheme'] == scheme)
            self.write(fixture_rows(job))
            records = normalize_dat(self.path, job)
            self.assertTrue(all(r['samples'] == 3 and r['warmups'] == 2 for r in records))
            rows = fixture_rows(job)
            next(r for r in rows if r['kind'] == 'sp')['samples'] = 11
            self.write(rows)
            with self.assertRaisesRegex(ValueError, 'samples must be 3'):
                normalize_dat(self.path, job)

    def test_legacy_rows_are_mapped_without_fabricated_provider_totals(self):
        job = next(j for j in self.jobs if j['scheme'] == 'pastau')
        self.write(fixture_rows(job))
        records = normalize_dat(self.path, job)
        update_wan = next(r for r in records if r['raw_phase'] == 'update_wan')
        self.assertEqual((update_wan['phase'], update_wan['panel']), ('pwdupd', 'wan'))
        self.assertFalse(next(r for r in records if r['phase'] == 'setup')['selected_for_pdf'])
        self.assertFalse(any(r['panel'] == 'provider' for r in records))
        response = next(r for r in records if r['raw_phase'] == 'auth_respond')
        self.assertEqual(response['components_for'], ['auth', 'pwdupd'])
        job = next(j for j in self.jobs if j['scheme'] == 'augsso')
        self.write(fixture_rows(job))
        records = normalize_dat(self.path, job)
        summary = next(r for r in records if r['raw_phase'] == 'update_total_p50sum')
        self.assertEqual(summary['statistic'], 'sum_of_calibrated_component_medians')
        self.assertNotIn('p95_ns', summary)

    def test_partial_wrong_coordinate_and_wrong_sample_files_fail(self):
        for scheme in ('upspa', 'pastau', 'augsso', 'roupspa'):
            job = next(j for j in self.jobs if j['scheme'] == scheme)
            base = fixture_rows(job)
            for field, value in [('scheme', 'wrong'), ('nsp', job['n'] + 1), ('samples', 1), ('qsp', 999), ('p50_ns', 'nan')]:
                rows = copy.deepcopy(base)
                rows[0][field] = value
                self.write(rows)
                with self.assertRaises(ValueError, msg=f'{scheme}:{field}'):
                    normalize_dat(self.path, job)
            self.write(base[:-1])
            with self.assertRaisesRegex(ValueError, 'missing required'):
                normalize_dat(self.path, job)

    def test_missing_component_duplicate_and_bad_profile_fail(self):
        job = next(j for j in self.jobs if j['scheme'] == 'pastau')
        rows = fixture_rows(job)
        self.write([r for r in rows if r['phase'] != 'update_handle'])
        with self.assertRaisesRegex(ValueError, 'missing required'):
            normalize_dat(self.path, job)
        self.write(rows + [rows[0]])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            normalize_dat(self.path, job)
        rows[-1]['net_profile'] = 'lan'
        self.write(rows)
        with self.assertRaisesRegex(ValueError, 'disagree'):
            normalize_dat(self.path, job)


if __name__ == '__main__':
    unittest.main()
