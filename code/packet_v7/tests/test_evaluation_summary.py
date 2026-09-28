"""Small deterministic selector/accounting fixtures, no experiment execution."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('evaluation_summary', ROOT / 'scripts/summarize_evaluation_v02.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class EvaluationSummaryTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT / 'tmp/tests'
        parent.mkdir(parents=True, exist_ok=True)
        self.directory = parent / ('summary-' + uuid.uuid4().hex)
        self.directory.mkdir()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for path in sorted(self.directory.rglob('*'), key=lambda p: len(p.parts), reverse=True):
            path.rmdir() if path.is_dir() else path.unlink()
        self.directory.rmdir()

    def test_selector_rejects_old_diagnostic_pilot_and_wrong_partitions(self):
        self.assertEqual(s.revision_partition('rev1_stage4_micro_netslab_20260923T120000Z_abcdef12'), ('micro', 'netslab', None))
        self.assertEqual(s.revision_partition('rev1_stage5_scaling_5gnidd_1000_20260923T120000Z_abcdef12'), ('scaling', '5gnidd', 1000))
        for name in ('stage4_micro_netslab_20260923T120000Z_abcdef12',
                     'diagnostic_scaling_5gnidd_1_20260923T120000Z_abcdef12',
                     'rev1_perf_pilot_netslab_micro_20260923T120000Z_abcdef12',
                     'rev1_stage5_load_netslab_2000_20260923T120000Z_abcdef12'):
            self.assertIsNone(s.revision_partition(name))

    def test_all_eighteen_partitions_required_no_best_duplicate_selection(self):
        candidates = [(key, str(key)) for key in s.expected_partitions()]
        selected, errors = s.select_unique_complete(candidates)
        self.assertEqual(len(selected), 18)
        self.assertEqual(errors, [])
        _, errors = s.select_unique_complete(candidates[:-1])
        self.assertEqual(errors[0]['reason'], 'missing')
        _, errors = s.select_unique_complete(candidates + candidates[:1])
        self.assertEqual(errors[0]['reason'], 'ambiguous_multiple_complete_runs')

    def test_exact_planned_process_cell_products(self):
        for key, count in s.expected_partitions().items():
            self.assertEqual(len(s.expected_job_signatures(key)), count)
        self.assertEqual(sum(s.expected_partitions().values()), 1820)

    def test_shared_source_snapshot_requires_identical_valid_hashes(self):
        digest = 'a' * 64
        self.assertEqual(s.require_shared_source_snapshot([digest] * 18), digest)
        self.assertIsNone(s.require_shared_source_snapshot([]))
        with self.assertRaisesRegex(s.SummaryError, 'inconsistent_final_performance_source_snapshots'):
            s.require_shared_source_snapshot([digest, 'b' * 64])
        with self.assertRaisesRegex(s.SummaryError, 'invalid_final_performance_source_snapshot_digest'):
            s.require_shared_source_snapshot(['not-a-sha256'])

    def test_cross_partition_source_mismatch_marks_synthesis_not_complete(self):
        protocol = self.directory / 'monitor_revision_protocol'
        protocol.mkdir()
        (protocol / 'ADDENDUM.md').write_text('Unit fixture selection rule.', encoding='utf-8')
        for mode, dataset, value in s.expected_partitions():
            label = f'rev1_stage4_micro_{dataset}' if mode == 'micro' else f'rev1_stage5_{mode}_{dataset}_{value}'
            (self.directory / (label + '_20260923T120000Z_abcdef12')).mkdir()
        def fake_partition(reader, directory, key):
            return {'run': directory.name, 'summary': {}, 'cells': [],
                    'source_snapshot_sha256': ('b' if key == ('micro', 'netslab', None) else 'a') * 64,
                    'plan_metadata': {'output_monitor_version': 'unit', 'design_sha256': 'same',
                                      'workload_manifest_sha256': 'same'}}
        with patch.object(s, 'FIXED_RUNS', {}), patch.object(s, 'verify_parent', return_value={}), \
                patch.object(s, 'performance_partition', side_effect=fake_partition):
            result = s.synthesize(self.directory, self.directory / 'report')
        self.assertEqual(result['status'], 'NOT_COMPLETE')
        self.assertEqual(len(result['selected_performance_runs']), 18)
        self.assertIsNone(result['shared_performance_source_snapshot_sha256'])
        self.assertIn('inconsistent_final_performance_source_snapshots', [error.get('reason') for error in result['errors']])

    def test_mean_of_block_percentiles_is_not_pooled_percentile(self):
        self.assertEqual(s.describe_blocks([10, 30]), {'blocks': 2, 'mean': 20, 'minimum': 10, 'maximum': 30})
        self.assertIsNone(s.describe_blocks([])['mean'])
        for invalid in (float('nan'), float('inf'), True):
            with self.assertRaises(ValueError):
                s.describe_blocks([invalid])

    def test_load_losses_and_censoring_keep_all_offered_denominator(self):
        cell = {'scheduled_measurement': 100, 'admitted_measurement': 80,
                'completed_measurement': 70, 'overflow_measurement': 20,
                'unfinished_at_drain_bound': 10, 'deadline_denominator': 100}
        values = s.validate_load_counts(cell)
        self.assertEqual(values['completed']['rate'], .7)
        self.assertEqual(values['overflow']['rate'], .2)
        self.assertEqual(values['right_censored']['rate'], .1)
        cell['deadline_denominator'] = 70
        with self.assertRaises(ValueError):
            s.validate_load_counts(cell)

    def test_strict_json_and_source_snapshots(self):
        path = self.directory / 'bad.json'
        path.write_text('{"x":1,"x":2}', encoding='utf-8')
        reader = s.Reader(self.directory)
        with self.assertRaises(ValueError):
            reader.json(path)
        for name, value in {'COMPLETE.json': {'status': 'COMPLETE', 'runner_exit_code': 0, 'failure': None,
                     'source_unchanged': True, 'baseline_after': {'status': 'pass'}},
                            'SOURCE_BEFORE.json': {'a': 'hash'}, 'SOURCE_AFTER.json': {'a': 'hash'}}.items():
            (self.directory / name).write_text(json.dumps(value), encoding='utf-8')
        s.verify_parent(reader, self.directory)
        (self.directory / 'SOURCE_AFTER.json').write_text('{"a":"changed"}', encoding='utf-8')
        with self.assertRaises(ValueError):
            s.verify_parent(s.Reader(self.directory), self.directory)

    def test_missing_campaign_produces_explicit_not_complete_artifacts(self):
        output = self.directory / 'report'
        result = s.synthesize(self.directory, output)
        self.assertEqual(result['status'], 'NOT_COMPLETE')
        self.assertTrue(result['errors'])
        self.assertIn('NOT_COMPLETE', (output / 'REPORT.md').read_text(encoding='utf-8'))
        manifest = json.loads((output / 'manifest.json').read_text())
        self.assertEqual(set(manifest['output_sha256']), {'analysis.json', 'REPORT.md'})
        self.assertEqual(manifest['generator']['path'], 'scripts/summarize_evaluation_v02.py')
        self.assertEqual(len(manifest['generator']['sha256']), 64)
        self.assertTrue(manifest['generator_unchanged_during_synthesis'])
        with self.assertRaises(FileExistsError):
            s.synthesize(self.directory, output)


if __name__ == '__main__':
    unittest.main()
