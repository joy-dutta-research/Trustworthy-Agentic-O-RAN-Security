"""Small fixture tests only: no production dataset or final experiment is run."""
from copy import deepcopy
import csv
import hashlib
import hmac
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from oran_trust_boundary import evaluation_datasets as d
from oran_trust_boundary.evaluation_cases import make_case, semantic_hash
from oran_trust_boundary.evaluation_reference import ReferencePolicy
from oran_trust_boundary.nidd_adapter import NiddValidationError, profile_archive
from oran_trust_boundary.nidd_cases import build_cases


def context(label='UDPFlood', rate=10000.0, row=1):
    return {'record_id': f'record-{row}', 'source_row_number': row, 'attack_type': label,
            'duration_seconds': 1.0, 'total_packets': int(rate), 'packets_per_second': rate}


class EvaluationDatasetsTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT / 'tmp' / 'tests'
        parent.mkdir(parents=True, exist_ok=True)
        self.directory = parent / ('evaluation-datasets-' + uuid.uuid4().hex)
        self.directory.mkdir()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        # Every path is owned by this test; do not touch unrelated tmp contents.
        for path in sorted(self.directory.rglob('*'), key=lambda p: len(p.parts), reverse=True):
            if path.is_dir():
                path.rmdir()
            else:
                path.unlink()
        self.directory.rmdir()

    def archive(self, rows=None, header=None, member='Combined.csv', raw=None):
        path = self.directory / (uuid.uuid4().hex + '.zip')
        if raw is None:
            buffer = io.StringIO(newline='')
            writer = csv.writer(buffer)
            writer.writerow(header or ['', 'Dur', 'TotPkts', 'Label', 'Attack Type', 'Unused'])
            writer.writerows(rows or [
                ['1', '1', '500', 'Benign', 'Benign', ''],
                ['2', '1', '100', 'Malicious', 'ICMPFlood', 'x'],
                ['3', '2', '600', 'Malicious', 'SYNFlood', 'x'],
                ['4', '1', '10000', 'Malicious', 'UDPFlood', 'x'],
                ['5', '1', '10000', 'Malicious', 'UDPFlood', 'x'],  # excluded index duplicate
                ['6', '0', '4', 'Malicious', 'UDPFlood', 'x'],
                ['7', '1', '4', 'Malicious', 'HTTPFlood', 'x'],
                ['8', '1', 'NaN', 'Malicious', 'SYNFlood', 'x'],
                ['9', '0', '0', 'Benign', 'Benign', 'x'],
            ])
            raw = buffer.getvalue().encode('utf-8-sig')
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(member, raw)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_stream_reconciles_frozen_adapter_counts_and_contexts(self):
        path, digest = self.archive()
        original = profile_archive(path, expected_sha256=digest, sample_per_label=100)
        audit = {}
        records = list(d.iter_eligible_records(path, audit, expected_sha256=digest))
        self.assertEqual(audit, original['audit'])
        self.assertEqual({c['record_id']: c for c, _ in records}, {c['record_id']: c for c in original['contexts']})
        self.assertEqual(len(records), 5)
        self.assertEqual(audit['duplicate_rows'], 1)
        self.assertEqual(audit['invalid_measurement_rows'], 1)
        self.assertTrue(all(set(c) == {'record_id', 'source_row_number', 'attack_type', 'duration_seconds', 'total_packets', 'packets_per_second'} for c, _ in records))

    def test_checksum_malformed_csv_encoding_labels_and_zip_fail_closed(self):
        path, digest = self.archive()
        with self.assertRaises(NiddValidationError):
            list(d.iter_eligible_records(path, {}, expected_sha256='0' * 64))
        for raw in (b'Dur,TotPkts,Label,Attack Type\n1,5,Benign,UDPFlood\n',
                    b'Dur,TotPkts,Label,Attack Type\n1,5,Benign\n',
                    b'Dur,TotPkts,Label,Attack Type\n"unclosed,5,Benign,Benign\n',
                    b'Dur,TotPkts,Label,Attack Type\n1,5,Benign,\xff\n'):
            with self.subTest(raw=raw):
                path, digest = self.archive(raw=raw)
                with self.assertRaises((NiddValidationError, UnicodeError)):
                    list(d.iter_eligible_records(path, {}, expected_sha256=digest))
        path, digest = self.archive(member='../Combined.csv')
        with self.assertRaises(NiddValidationError):
            list(d.iter_eligible_records(path, {}, expected_sha256=digest))

    def test_duplicate_required_headers_rejected(self):
        path, digest = self.archive(raw=b'Dur,Dur,TotPkts,Label,Attack Type\n1,1,5,Benign,Benign\n')
        with self.assertRaises(NiddValidationError):
            list(d.iter_eligible_records(path, {}, expected_sha256=digest))

    def test_source_change_after_initial_check_is_detected(self):
        path, digest = self.archive()
        records = d.iter_eligible_records(path, {}, expected_sha256=digest)
        next(records)
        with path.open('ab') as handle:
            handle.write(b'changed')
        with self.assertRaises(NiddValidationError):
            list(records)

    def test_original_proposals_and_groups_are_semantically_unchanged(self):
        reference, evaluator = ReferencePolicy(), d.EvaluatorBundle()
        for c in [context('Benign', 100, 1), context('ICMPFlood', 50, 2), context('SYNFlood', 10000, 3), context('UDPFlood', 20000, 4)]:
            old, new = build_cases([c]), d.make_nidd_groups(c)
            for group in old:
                for before, after in zip(old[group], new[group]):
                    self.assertEqual(before['proposal'], after['proposal'])
                    self.assertEqual(before['active_actions'], after['active_actions'])
                    after = d.attach_reference(after, reference)
                    observed = evaluator.evaluate(after)['trust_boundary']
                    self.assertEqual(observed['decision'], before['expected_decision'])
                    self.assertEqual(observed['decision'], after['expected_decision'])
                    self.assertEqual(set(observed['reasons']), set(after['expected_reasons']))
            self.assertEqual(d.natural_case(c)['proposal'], old['record_proposals'][0]['proposal'])

    def test_budget_variant_does_not_move_fixed_probes_or_ceiling(self):
        c = context(rate=10000)
        self.assertEqual(d.raw_reduction(10000, 500), 95)
        self.assertEqual(d.raw_reduction(10000, 2000), 80)
        self.assertEqual(d.raw_reduction(1e-300, 500), 1)
        groups = d.make_nidd_groups(c, 500)
        self.assertEqual(groups['record_proposals'][0]['proposal']['parameters']['reduction_percent'], 95)
        self.assertEqual(groups['conformance'][0]['proposal']['parameters']['reduction_percent'], 80)
        self.assertEqual(groups['conformance'][3]['proposal']['parameters']['reduction_percent'], 95)
        benign = d.make_nidd_groups(context('Benign', 100), 500)
        self.assertEqual(benign['false_alarm_probes'][0]['proposal']['parameters']['reduction_percent'], 30)
        self.assertEqual(groups['record_proposals'][0]['source_context']['proposal_generation']['packet_budget_per_second'], 500)

    def test_seeded_ranking_is_independently_encoded_and_order_invariant(self):
        panels = d.SeedPanels(seeds=[0, 1], capacity=2)
        reverse = d.SeedPanels(seeds=[0, 1], capacity=2)
        values = [(context(label, 1000 + row, row), hashlib.sha256(str(row).encode()).digest())
                  for label in d.SELECTED_LABELS for row in range(1, 6)]
        for c, digest in values:
            panels.add(c, digest, {})
        for c, digest in reversed(values):
            reverse.add(c, digest, {})
        self.assertEqual(panels.export(), reverse.export())
        exported = panels.export()
        for seed in (0, 1):
            key = b'5gnidd-keyed-rank/1\x00' + seed.to_bytes(4, 'big')
            independently = sorted((hmac.new(key, bytes.fromhex(d.ARCHIVE_SHA256) + digest, hashlib.sha256).hexdigest(), c['source_row_number'])
                                   for c, digest in values if c['attack_type'] == 'Benign')[:2]
            actual = exported['seeds'][str(seed)]['Benign']
            self.assertEqual([(e['rank_sha256'], e['context']['source_row_number']) for e in actual], independently)
            self.assertEqual(len(actual), 2)
        self.assertEqual(exported['sampling_spec_sha256'], d.canonical_digest(d.SAMPLING_SPEC))

    def test_seed_panel_rejects_incomplete_classes_and_invalid_settings(self):
        with self.assertRaises(ValueError):
            d.SeedPanels(seeds=[0, 0])
        with self.assertRaises(ValueError):
            d.SeedPanels(seeds=[True])
        with self.assertRaises(ValueError):
            d.SeedPanels(capacity=251)
        with self.assertRaises(ValueError):
            d.SeedPanels(seeds=[0], capacity=1).export()

    def test_metrics_null_denominators_and_false_alarm_separation(self):
        case = d.attach_reference(d.make_nidd_groups(context('Benign', 100))['false_alarm_probes'][0], ReferencePolicy())
        outcomes = d.EvaluatorBundle().evaluate(case)
        metrics = d.Metrics()
        metrics.add(case, outcomes)
        summary = metrics.summary()['groups']['false_alarm_probes']['overall']['trust_boundary']
        self.assertIsNone(summary['compliant_action_acceptance'])
        self.assertEqual(summary['benign_disruptive_admission'], {'numerator': 1, 'denominator': 1, 'rate': 1.0})
        self.assertIsNone(summary['policy_block_required_admissions']['rate'])
        self.assertEqual(summary['policy_block_required_admissions']['denominator'], 0)

    def test_poststratification_weights_conditional_denominator_fractions(self):
        # A has many eligible records but only 10% need blocking; B has all 100%.
        # Averaging A's 100% and B's 0% at 90:10 weights gives a wrong 90%.
        result = d.poststratified_rate({'A': d.rate(1, 1), 'B': d.rate(0, 20)},
                                       {'A': 10, 'B': 20}, {'A': 900, 'B': 100})
        self.assertAlmostEqual(result['rate'], 90 / 190)
        self.assertEqual(result['estimated_release_numerator_exact'], {'numerator': 90, 'denominator': 1})
        self.assertEqual(result['estimated_release_denominator_exact'], {'numerator': 190, 'denominator': 1})
        empty = d.poststratified_rate({'A': d.rate(0, 0)}, {'A': 10}, {'A': 900})
        self.assertIsNone(empty['rate'])
        with self.assertRaises(ValueError):
            d.poststratified_rate({'A': d.rate(2, 11)}, {'A': 10}, {'A': 900})

    def test_checked_configuration_count_ignores_only_source_identity(self):
        a = d.natural_case(context(row=1))
        b = d.natural_case(context(row=2))
        self.assertEqual(semantic_hash(a), semantic_hash(b))
        b['proposal']['parameters']['reduction_percent'] = 60
        self.assertNotEqual(semantic_hash(a), semantic_hash(b))

    def test_ofat_recomputes_reference_and_does_not_modify_primary_policy(self):
        original = (ROOT / 'configs/paper_policy.json').read_bytes()
        case = d.make_nidd_groups(context(rate=10000))['conformance'][0]
        for condition, expected in [('original', 'ALLOW'), ('reduction60', 'DENY'), ('reduction90', 'ALLOW'), ('ttl300', 'ALLOW'), ('ttl600', 'ALLOW')]:
            reference, policy, budget = d.condition_settings(condition)
            candidate = d.attach_reference(case, reference)
            self.assertEqual(candidate['proposal']['parameters']['reduction_percent'], 80)
            self.assertEqual(candidate['expected_decision'], expected)
            self.assertEqual(d.EvaluatorBundle(policy).evaluate(candidate)['trust_boundary']['decision'], expected)
            self.assertEqual(budget, 1000)
        self.assertEqual((ROOT / 'configs/paper_policy.json').read_bytes(), original)

    def test_approval_semantics_survive_per_case_gate_cache(self):
        evaluator = d.EvaluatorBundle()
        case = make_case('isolate_xapp', 'approved-fixture')
        self.assertEqual(evaluator.evaluate(case)['trust_boundary']['decision'], 'ALLOW')
        changed = deepcopy(case)
        changed['proposal']['parameters']['duration_seconds'] += 1
        result = evaluator.evaluate(changed)['trust_boundary']
        self.assertEqual(result['decision'], 'ESCALATE')
        self.assertIn('HUMAN_APPROVAL_BINDING_MISMATCH', result['reasons'])

    def test_exclusive_run_provenance_and_output_bound(self):
        source = self.directory / 'input.json'
        source.write_text('{}', encoding='utf-8')
        output = self.directory / 'run'
        run = d.EvaluationRun(output, 'UNIT_FIXTURE_NOT_EXPERIMENT', {'fixture': source}, large=False)
        run.write_json('tiny.json', {'hello': 'world'})
        run.finish(True)
        receipt = json.loads((output / 'RUN.json').read_text())
        self.assertEqual(receipt['status'], 'COMPLETE')
        self.assertTrue(receipt['inputs_and_source_unchanged'])
        self.assertNotIn(str(ROOT), (output / 'RUN.json').read_text())
        with self.assertRaises(FileExistsError):
            d.EvaluationRun(output, 'UNIT_FIXTURE', {}, large=False)
        run2 = d.EvaluationRun(self.directory / 'bounded', 'UNIT_FIXTURE', {}, large=False)
        run2.limit = run2.output_bytes + 2
        with self.assertRaises(RuntimeError):
            run2.write_json('oversize.json', {'too': 'large'})
        run2.finish(False, error_type='RuntimeError')
        self.assertEqual(json.loads((run2.output / 'RUN.json').read_text())['status'], 'INCOMPLETE')

    def test_changed_input_and_missing_rss_monitor_never_pass(self):
        source = self.directory / 'input.json'
        source.write_text('{}', encoding='utf-8')
        run = d.EvaluationRun(self.directory / 'changed', 'UNIT_FIXTURE', {'fixture': source}, large=False)
        source.write_text('{"changed":true}', encoding='utf-8')
        with self.assertRaises(RuntimeError):
            run.finish(True)
        self.assertEqual(json.loads((run.output / 'RUN.json').read_text())['status'], 'INCOMPLETE')
        output = self.directory / 'unsupported'
        with patch.object(d, 'worker_rss_bytes', side_effect=RuntimeError('not available')):
            with self.assertRaises(RuntimeError):
                d.EvaluationRun(output, 'UNIT_FIXTURE', {}, large=False)
        self.assertEqual(json.loads((output / 'RUN.json').read_text())['status'], 'INCOMPLETE')

    def test_jsonl_duplicate_keys_and_oversized_lines_fail(self):
        for raw in ('{"case_id":"x","case_id":"y","proposal":{},"evaluation_time":"x"}\n',
                    '{"x":"' + 'z' * (1024**2) + '"}\n'):
            path = self.directory / (uuid.uuid4().hex + '.jsonl')
            path.write_text(raw, encoding='utf-8')
            with self.assertRaises(ValueError):
                list(d.iter_frozen_cases([path]))

    def test_panel_loader_validates_ranks_counts_and_sanitized_context(self):
        collector = d.SeedPanels()
        for label_index, label in enumerate(d.SELECTED_LABELS):
            for offset in range(250):
                row = label_index * 250 + offset + 1
                c = context(label, 1000 + row, row)
                collector.add(c, hashlib.sha256(str(row).encode()).digest(),
                              {'proposal_sha256': d.canonical_digest(d.natural_case(c)['proposal'])})
        panels = collector.export()
        path = self.directory / 'panels.json'
        path.write_bytes(d.encoded_json(panels))
        self.assertEqual(d.load_panels(path)['capacity'], 250)
        entry = panels['seeds']['0']['Benign'][0]
        entry['context']['ip_address'] = 'must-not-export'
        path.write_bytes(d.encoded_json(panels))
        with self.assertRaises(ValueError):
            d.load_panels(path)
        del entry['context']['ip_address']
        original_digest = entry['proposal_sha256']
        entry['proposal_sha256'] = '0' * 64
        path.write_bytes(d.encoded_json(panels))
        with self.assertRaises(ValueError):
            d.load_panels(path)
        entry['proposal_sha256'] = original_digest
        entry['rank_sha256'] = '0' * 64
        path.write_bytes(d.encoded_json(panels))
        with self.assertRaises(ValueError):
            d.load_panels(path)

    def test_panel_metrics_reuse_cached_outcomes_without_evaluator_calls(self):
        collector = d.SeedPanels(seeds=[0, 1], capacity=25)
        evaluator, reference = d.EvaluatorBundle(), ReferencePolicy()
        for label_index, label in enumerate(d.SELECTED_LABELS):
            for offset in range(30):
                row = label_index * 30 + offset + 1
                c = context(label, 10000 + row, row)
                case = d.attach_reference(d.natural_case(c), reference)
                collector.add(c, hashlib.sha256(str(row).encode()).digest(),
                              {'proposal_sha256': d.canonical_digest(case['proposal']),
                               'expected_reference': case['expected_reference'], 'outcomes': evaluator.evaluate(case)})
        with patch.object(d.EvaluatorBundle, 'evaluate', side_effect=AssertionError('must not re-evaluate cached census cases')):
            analysis = d.panel_analysis(collector.export())
        self.assertEqual(set(analysis['by_seed_and_size']), {'0', '1'})
        point = analysis['by_seed_and_size']['0']['25']
        self.assertEqual(point['sample_counts'], {label: 25 for label in d.SELECTED_LABELS})
        self.assertEqual(point['weighted_class_rates']['trust_boundary']['decision_agreement']['eligible_release_poststratified']['rate'], 1)
        self.assertLessEqual(analysis['overlap_by_label_and_size']['Benign']['25']['unique_record_union'], 30)

    def test_completed_netslab_input_verifies_status_all_hashes_and_supervisor(self):
        parent = self.directory / 'supervised'
        child = parent / 'work'
        child.mkdir(parents=True)
        artifacts = ('cases.jsonl', 'decisions.jsonl', 'summary.json', 'REPORT.md')
        for name in artifacts:
            (child / name).write_text('fixture\n', encoding='utf-8')
        receipt = {'status': 'COMPLETED_WITH_FINDINGS', 'mode': 'netslab', 'constructed_case_count': 20000,
                   'files': {name: {'sha256': d.sha256_file(child / name)} for name in artifacts}}
        (child / 'COMPLETE.json').write_bytes(d.encoded_json(receipt))
        (parent / 'COMPLETE.json').write_bytes(d.encoded_json({'status': 'COMPLETE', 'source_unchanged': True,
                                                             'baseline_after': {'status': 'pass'}}))
        self.assertEqual(d.verify_netslab_input(child)['cases'], child / 'cases.jsonl')
        (child / 'REPORT.md').write_text('changed', encoding='utf-8')
        with self.assertRaises(ValueError):
            d.verify_netslab_input(child)
        receipt['status'] = 'PILOT_NOT_CONFIRMATORY'
        (child / 'COMPLETE.json').write_bytes(d.encoded_json(receipt))
        with self.assertRaises(ValueError):
            d.verify_netslab_input(child)

    def test_census_consumer_requires_correct_stage_denominators_and_supervisor(self):
        parent = self.directory / 'census-supervised'
        child = parent / 'work'
        child.mkdir(parents=True)
        (child / 'panels.json').write_text('{}', encoding='utf-8')
        receipt = {'status': 'COMPLETE', 'inputs_and_source_unchanged': True,
                   'stage': 'stage2a_5gnidd_census', 'audit_reconciled': True,
                   'progress': {'evaluated_records': 733693, 'source_rows': 1215890, 'comparator_decisions': 2934772},
                   'input_sha256_before': {'archive': d.ARCHIVE_SHA256},
                   'input_sha256_after': {'archive': d.ARCHIVE_SHA256},
                   'output_sha256': {'panels.json': d.sha256_file(child / 'panels.json')}}
        (child / 'RUN.json').write_bytes(d.encoded_json(receipt))
        (parent / 'COMPLETE.json').write_bytes(d.encoded_json({'status': 'COMPLETE', 'source_unchanged': True,
                                                             'baseline_after': {'status': 'pass'}}))
        d.verify_completed_input(child, ['panels.json'])
        for key, value in [('stage', 'stage2b_5gnidd_conformance'), ('audit_reconciled', False)]:
            invalid = deepcopy(receipt)
            invalid[key] = value
            (child / 'RUN.json').write_bytes(d.encoded_json(invalid))
            with self.assertRaises(ValueError):
                d.verify_completed_input(child, ['panels.json'])
        (child / 'RUN.json').write_bytes(d.encoded_json(receipt))
        (parent / 'COMPLETE.json').write_bytes(d.encoded_json({'status': 'INCOMPLETE'}))
        with self.assertRaises(ValueError):
            d.verify_completed_input(child, ['panels.json'])

    def test_instrumentation_pilot_pipeline_never_publishes_census_panels(self):
        path = self.directory / 'fixture.zip'
        path.write_bytes(b'unit fixture input; source iterator mocked')
        def tiny_iterator(archive, audit, **kwargs):
            for row in range(1, 3):
                audit['row_count'] = row
                yield context('Benign', 100, row), hashlib.sha256(str(row).encode()).digest()
        output = self.directory / 'pilot'
        with patch.object(d, 'iter_eligible_records', tiny_iterator):
            d.run_census(path, output, pilot_records=2)
        receipt = json.loads((output / 'RUN.json').read_text())
        summary = json.loads((output / 'summary.json').read_text())
        self.assertEqual(receipt['scientific_status'], 'PILOT_NOT_CONFIRMATORY')
        self.assertFalse(receipt['audit_reconciled'])
        self.assertEqual(summary['instrumentation_records'], 2)
        self.assertEqual(len((output / 'census_decisions.jsonl').read_text().splitlines()), 2)
        self.assertFalse((output / 'panels.json').exists())
        self.assertTrue(summary['partial_csv_not_fully_crc_validated_or_audit_reconciled'])


if __name__ == '__main__':
    unittest.main()
