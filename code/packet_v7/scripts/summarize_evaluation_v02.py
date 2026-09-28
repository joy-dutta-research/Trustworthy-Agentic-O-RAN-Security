"""Compact-summary-only synthesis of the frozen v0.2 campaign.

No raw request CSV/JSONL is read or claimed to be independently verified. Final
performance selection is restricted to the predeclared monitor-revision labels;
an unfavorable completed result is retained, never replaced by a faster run.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import itertools
import json
import math
from pathlib import Path
import re
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
METHODS = ('direct', 'contract', 'contract_rbac', 'trust_boundary')
BOUNDARIES = ('evaluator_component', 'matched_local_processing_with_buffered_event_logging')
DATASETS = ('netslab', '5gnidd')
FIXED_RUNS = {
    'validity': 'stage1_validity_20260923T101717Z_f62545ac',
    'netslab': 'stage2_netslab_20260923T101734Z_08a19383',
    'census': 'stage2_nidd_census_20260923T101817Z_8b8ce16b',
    'panels': 'stage2_nidd_panels_20260923T102414Z_8f176b45',
    'sensitivity:netslab:original': 'stage3_netslab_original_20260923T102524Z_e1d633d2',
    'sensitivity:netslab:reduction60': 'stage3_netslab_reduction60_20260923T102540Z_9dd206c8',
    'sensitivity:netslab:reduction90': 'stage3_netslab_reduction90_20260923T102556Z_adc71617',
    'sensitivity:netslab:ttl300': 'stage3_netslab_ttl300_20260923T102612Z_1e37d8a7',
    'sensitivity:netslab:ttl600': 'stage3_netslab_ttl600_20260923T102628Z_edda31c3',
    'sensitivity:nidd:original': 'stage3_nidd_original_20260923T102644Z_59811f0f',
    'sensitivity:nidd:reduction60': 'stage3_nidd_reduction60_20260923T102751Z_7ce7e6e1',
    'sensitivity:nidd:reduction90': 'stage3_nidd_reduction90_20260923T102856Z_eb7de4a0',
    'sensitivity:nidd:ttl300': 'stage3_nidd_ttl300_20260923T103002Z_9e1abec7',
    'sensitivity:nidd:ttl600': 'stage3_nidd_ttl600_20260923T103115Z_e167c981',
    'sensitivity:nidd:budget500': 'stage3_nidd_budget500_20260923T103226Z_f5de7c58',
    'sensitivity:nidd:budget2000': 'stage3_nidd_budget2000_20260923T103354Z_51b62995',
}
LIMITATIONS = [
    'Policy conformance under illustrative operator assumptions is not incident truth, mitigation necessity or operational safety.',
    'Constructed variants, overlapping source panels and repeated calls are not independent safety trials; no safety-probability confidence interval is inferred.',
    'The census contains only eligible Benign/ICMPFlood/SYNFlood/UDPFlood records; unsupported labels and zero/undefined attack packet rates remain excluded.',
    'All control identities, slices, authorities and state are simulated. No learned detector, LLM planner, live E2/A1 integration or radio service outcome is validated.',
    'Natural proposals and controlled violations remain separate. Zero required-block denominators are null, not successful blocking evidence.',
    'False-alarm admissions remain a limitation group, not safe-action successes. Audit checksums are not signatures or evidence authentication.',
    'Timing is local host/workload evidence. Buffered event logging is not durable persistence; there is no hard-real-time or production-capacity claim.',
    'Process-block percentile means are not pooled request percentiles; paired differences of percentiles are not percentiles of per-request overhead.',
    'Load latency percentiles describe completed requests only. Overflow and right-censored requests remain in all-offered denominators; generator-limited conditions are retained.',
    'This report hashes and checks compact summaries/receipts only. It does not reread or independently recompute raw CSV/JSONL observations.',
]


class SummaryError(ValueError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SummaryError('duplicate JSON key')
        result[key] = value
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


class Reader:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.manifest = {}

    def bytes(self, path: Path, maximum=64 * 1024**2):
        path = path.absolute()
        if not path.is_relative_to(self.root):
            raise SummaryError('input is outside the declared results root')
        for ancestor in (path, *path.parents):
            if ancestor.is_symlink() or getattr(ancestor, 'is_junction', lambda: False)():
                raise SummaryError('linked input paths are not permitted')
            if ancestor == self.root:
                break
        before = path.stat()
        if not path.is_file() or before.st_size > maximum:
            raise SummaryError('input is not a bounded regular file')
        raw = path.read_bytes()
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or len(raw) != before.st_size:
            raise SummaryError('input changed during read')
        relative = path.relative_to(self.root).as_posix()
        digest = hashlib.sha256(raw).hexdigest()
        if relative in self.manifest and self.manifest[relative]['sha256'] != digest:
            raise SummaryError('input changed between reads')
        self.manifest[relative] = {'sha256': digest, 'bytes': len(raw)}
        return raw

    def json(self, path: Path):
        def bad_constant(_):
            raise SummaryError('nonfinite JSON number')
        try:
            return json.loads(self.bytes(path).decode('utf-8'), object_pairs_hook=_pairs, parse_constant=bad_constant)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise SummaryError('invalid UTF-8 JSON input') from exc

    def digest(self, path):
        self.bytes(path)
        return self.manifest[path.absolute().relative_to(self.root).as_posix()]['sha256']


def expected_partitions():
    result = {}
    for dataset in DATASETS:
        result[('micro', dataset, None)] = 160
        for size in (0, 1, 10, 100, 1000):
            result[('scaling', dataset, size)] = 80 if size == 0 else 160
        for rate in (100, 1000, 5000):
            result[('load', dataset, rate)] = 10
    return result


def revision_partition(name: str):
    suffix = r'_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8}'
    micro = re.fullmatch(r'rev1_stage4_micro_(netslab|5gnidd)' + suffix, name)
    if micro:
        return ('micro', micro[1], None)
    match = re.fullmatch(r'rev1_stage5_(scaling|load)_(netslab|5gnidd)_([0-9]+)' + suffix, name)
    if match:
        key = (match[1], match[2], int(match[3]))
        if key in expected_partitions():
            return key
    return None


def select_unique_complete(candidates):
    """Never prefer a faster/favorable duplicate or silently fill a missing cell."""
    grouped = defaultdict(list)
    for key, path in candidates:
        grouped[key].append(path)
    errors = []
    selected = {}
    for key in expected_partitions():
        matches = grouped.get(key, [])
        if len(matches) != 1:
            errors.append({'partition': list(key), 'complete_candidates': len(matches),
                           'reason': 'missing' if not matches else 'ambiguous_multiple_complete_runs'})
        else:
            selected[key] = matches[0]
    return selected, errors


def require_shared_source_snapshot(hashes):
    """Require byte-identical frozen source inventories across final partitions."""
    hashes = list(hashes)
    if not hashes:
        return None  # Missing partitions are independently reported as NOT_COMPLETE.
    if any(not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{64}', value) is None for value in hashes):
        raise SummaryError('invalid_final_performance_source_snapshot_digest')
    if len(set(hashes)) != 1:
        raise SummaryError('inconsistent_final_performance_source_snapshots')
    return hashes[0]


def verify_parent(reader, directory):
    receipt = reader.json(directory / 'COMPLETE.json')
    before = reader.json(directory / 'SOURCE_BEFORE.json')
    after = reader.json(directory / 'SOURCE_AFTER.json')
    if (receipt.get('status') != 'COMPLETE' or receipt.get('runner_exit_code') != 0
            or receipt.get('source_unchanged') is not True or receipt.get('failure') is not None
            or receipt.get('baseline_after', {}).get('status') != 'pass' or before != after):
        raise SummaryError('parent execution/source/baseline provenance is incomplete')
    return receipt


def verify_child_summary(reader, directory, kind):
    verify_parent(reader, directory)
    work = directory / 'work'
    summary = reader.json(work / 'summary.json')
    digest = reader.digest(work / 'summary.json')
    if kind in ('validity', 'netslab'):
        receipt = reader.json(work / 'COMPLETE.json')
        if (receipt.get('status') not in ('COMPLETED', 'COMPLETED_WITH_FINDINGS')
                or receipt.get('mode') != ('validity' if kind == 'validity' else 'netslab')
                or receipt.get('files', {}).get('summary.json', {}).get('sha256') != digest
                or receipt.get('constructed_case_count') != summary.get('constructed_case_count')):
            raise SummaryError('constructed-suite completion/summary binding mismatch')
    else:
        receipt = reader.json(work / 'RUN.json')
        if (receipt.get('status') != 'COMPLETE' or receipt.get('inputs_and_source_unchanged') is not True
                or receipt.get('input_sha256_before') != receipt.get('input_sha256_after')
                or receipt.get('source_files_before') != receipt.get('source_files_after')
                or receipt.get('output_sha256', {}).get('summary.json') != digest):
            raise SummaryError('dataset completion/summary binding mismatch')
        if kind == 'census' and (receipt.get('stage') != 'stage2a_5gnidd_census'
                                or receipt.get('audit_reconciled') is not True
                                or receipt.get('progress', {}).get('evaluated_records') != 733693):
            raise SummaryError('census is incomplete or unreconciled')
        if kind == 'panels' and (receipt.get('stage') != 'stage2b_5gnidd_conformance'
                                or receipt.get('conformance_proposals') != 95000
                                or receipt.get('false_alarm_proposals') != 5000):
            raise SummaryError('panel denominators are incomplete')
        if kind.startswith('sensitivity:'):
            _, source, condition = kind.split(':')
            if receipt.get('stage') != f'stage3_{source}_{condition}' or summary.get('condition') != condition:
                raise SummaryError('sensitivity condition binding mismatch')
    return summary, receipt


def job_signature(job):
    return tuple(job.get(key) for key in ('mode', 'dataset', 'block', 'seed', 'method', 'boundary',
                                          'state_size', 'state_path', 'large_input', 'resource_only', 'rate'))


def expected_job_signatures(key):
    mode, dataset, value = key
    jobs = []
    for block in range(20 if mode == 'micro' else 5):
        common = {'mode': mode, 'dataset': dataset, 'block': block,
                  'seed': (2000 if mode == 'micro' else 3000 if mode == 'scaling' else 4000) + block}
        if mode == 'micro':
            jobs.extend({**common, 'method': m, 'boundary': b} for m, b in itertools.product(METHODS, BOUNDARIES))
        elif mode == 'scaling':
            paths = ('no_conflict',) if value == 0 else ('no_conflict', 'conflict_first', 'conflict_last', 'malformed_last')
            large = (False, True) if value == 0 else (False,)
            jobs.extend({**common, 'method': m, 'boundary': BOUNDARIES[0], 'state_size': value,
                         'state_path': p, 'large_input': big, 'resource_only': resource}
                        for m, p, big, resource in itertools.product(METHODS, paths, large, (False, True)))
        else:
            jobs.extend({**common, 'method': m, 'boundary': BOUNDARIES[1], 'rate': value, 'state_size': 100}
                        for m in ('direct', 'trust_boundary'))
    return {job_signature(job) for job in jobs}


def finite(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise SummaryError('finite metric required')
    return value


def describe_blocks(values):
    values = [finite(value) for value in values]
    return {'blocks': len(values), 'mean': statistics.fmean(values) if values else None,
            'minimum': min(values) if values else None, 'maximum': max(values) if values else None}


def validate_load_counts(cell):
    offered, admitted, completed, dropped, censored = (cell[key] for key in (
        'scheduled_measurement', 'admitted_measurement', 'completed_measurement',
        'overflow_measurement', 'unfinished_at_drain_bound'))
    if any(type(v) is not int or v < 0 for v in (offered, admitted, completed, dropped, censored)):
        raise SummaryError('load counts must be nonnegative integers')
    if offered <= 0 or offered != admitted + dropped or admitted != completed + censored:
        raise SummaryError('all-offered load accounting does not reconcile')
    if cell.get('deadline_denominator') != offered:
        raise SummaryError('deadline denominator differs from all offered requests')
    return {'completed': {'numerator': completed, 'denominator': offered, 'rate': completed / offered},
            'overflow': {'numerator': dropped, 'denominator': offered, 'rate': dropped / offered},
            'right_censored': {'numerator': censored, 'denominator': offered, 'rate': censored / offered}}


def performance_partition(reader, directory, key):
    verify_parent(reader, directory)
    work = directory / 'work'
    receipt, summary, plan = (reader.json(work / name) for name in ('COMPLETE.json', 'summary.json', 'run_plan.json'))
    expected_count = expected_partitions()[key]
    mode, dataset, value = key
    if (receipt.get('status') not in ('complete', 'completed_with_reference_disagreement')
            or receipt.get('mode') != mode or summary.get('status') != receipt.get('status')
            or summary.get('scientific_scope') != 'PREDECLARED_EVALUATION_PARTITION'
            or summary.get('completed_cells') != expected_count or summary.get('planned_cells') != expected_count
            or len(plan.get('jobs', [])) != expected_count
            or len(summary.get('cell_summaries', [])) != expected_count):
        raise SummaryError('performance partition status/cell counts mismatch')
    signatures = [job_signature(job) for job in plan['jobs']]
    if len(set(signatures)) != expected_count or set(signatures) != expected_job_signatures(key):
        raise SummaryError('missing, duplicate or unexpected planned process cells')
    if not plan.get('output_monitor_version') or summary.get('output_monitor_version') != plan['output_monitor_version']:
        raise SummaryError('revised monitor version is absent or inconsistent')
    cells = []
    for index, (entry, job) in enumerate(zip(summary['cell_summaries'], plan['jobs'])):
        if entry.get('directory') != f'cell_{index:04d}':
            raise SummaryError('unexpected cell directory order/name')
        cell = reader.json(work / entry['directory'] / 'summary.json')
        if (cell.get('status') not in ('complete', 'completed_with_reference_disagreement')
                or cell.get('status') != entry.get('status') or cell.get('job') != job):
            raise SummaryError('cell summary does not bind the planned job')
        if mode == 'load':
            if (job.get('measurement_seconds') != 60 or job.get('warmup_seconds') != 10
                    or job.get('drain_seconds') != 30 or job.get('queue_capacity') != 1000
                    or cell.get('scheduled_measurement') != value * 60):
                raise SummaryError('load duration/rate/queue differs from frozen design')
            validate_load_counts(cell)
        elif (job.get('measured') != (10000 if mode == 'micro' else 1000)
              or job.get('warmup') != (1000 if mode == 'micro' else 100)
              or cell.get('reference_total') != job['measured']):
            raise SummaryError('timing/scaling request counts differ from design')
        if mode != 'load' and not job.get('resource_only') and cell.get('timing', {}).get('sample_count') != job['measured']:
            raise SummaryError('timing sample count differs from completed request count')
        cells.append(cell)
    return {'partition': list(key), 'run': directory.name, 'summary': summary,
            'source_snapshot_sha256': reader.digest(directory / 'SOURCE_BEFORE.json'),
            'plan_metadata': {k: v for k, v in plan.items() if k != 'jobs'}, 'cells': cells}


def compact_dataset_summary(summary):
    base = summary.get('overall', summary)
    return {'scientific_status': base.get('scientific_status', summary.get('status')),
            'trust_boundary_findings': base.get('trust_boundary_findings'),
            'groups': {name: {'overall': group['overall'],
                              'distinct_meaningful_configurations_union': group.get('distinct_meaningful_configurations_union'),
                              'distinct_meaningful_configurations': group.get('distinct_meaningful_configurations')}
                       for name, group in base.get('groups', {}).items()},
            'assumption_effect_on_fixed_inputs': summary.get('assumption_effect_on_fixed_inputs'),
            'proposal_counts': summary.get('proposal_counts')}


def aggregate_performance(partitions):
    grouped = defaultdict(list)
    load_rows, comparisons, disagreements = [], [], []
    for partition in partitions:
        comparisons.extend({'run': partition['run'], **comparison} for comparison in partition['summary'].get('comparisons', []))
        for cell in partition['cells']:
            job = cell['job']
            if cell['status'] != 'complete':
                disagreements.append({'run': partition['run'], 'job': job, 'status': cell['status']})
            if job['mode'] == 'load':
                endpoint = cell['consumer_endpoint_metrics']
                load_rows.append({'run': partition['run'], 'dataset': job['dataset'], 'method': job['method'],
                    'seed': job['seed'], 'block': job['block'], 'offered_per_second': job['rate'],
                    'counts': {name: cell[name] for name in ('scheduled_measurement', 'admitted_measurement',
                        'completed_measurement', 'overflow_measurement', 'unfinished_at_drain_bound', 'late_completions_during_cleanup_grace')},
                    'all_offered_fractions': validate_load_counts(cell), 'generator_limited': cell['generator_limited'],
                    'generator_lateness': cell['generator_lateness'], 'generator_high_lateness_fraction': cell['generator_high_lateness_fraction'],
                    'completion_latency_completed_only': endpoint['completion_latency'],
                    'queue_latency_completed_only': endpoint['queue_latency'], 'service_latency_completed_only': endpoint['service_latency'],
                    'deadline_success_fractions_all_offered': cell['deadline_success_fractions'],
                    'completed_reference_agreement': {'numerator': endpoint['reference_agreement_count'], 'denominator': cell['completed_measurement']},
                    'maximum_admitted_not_completed': cell['maximum_admitted_not_completed_from_trace'],
                    'producer_peak_rss_bytes': cell['producer_peak_rss'],
                    'consumer_peak_rss_bytes': cell['consumer_raw_summary_including_cleanup_grace']['peak_resident_bytes'],
                    'producer_cpu_seconds': cell['producer_cpu_seconds'],
                    'consumer_cpu_seconds': cell['consumer_raw_summary_including_cleanup_grace']['cpu_seconds'],
                    'completion_count_divided_by_offering_window_not_capacity': cell['completion_count_divided_by_offering_window'],
                    'measurement_cohort_completions_inside_offering_window_per_second': cell['actual_measurement_cohort_completions_per_offering_second']})
            else:
                key = tuple(job.get(k) for k in ('mode', 'dataset', 'boundary', 'method', 'state_size', 'state_path', 'large_input', 'resource_only'))
                grouped[key].append(cell)
    timing = []
    names = ('mode', 'dataset', 'boundary', 'method', 'state_size', 'state_path', 'large_input', 'resource_only')
    for key, cells in sorted(grouped.items(), key=lambda item: str(item[0])):
        row = dict(zip(names, key))
        row.update(blocks=len(cells), measured_requests=sum(cell['reference_total'] for cell in cells),
                   reference_agreement_count=sum(cell['reference_agreement_count'] for cell in cells),
                   peak_rss_bytes=describe_blocks([cell['peak_resident_bytes'] for cell in cells]),
                   cpu_seconds_including_instrumentation=describe_blocks([cell['cpu_seconds_including_instrumentation'] for cell in cells]))
        if not row['resource_only']:
            row['block_percentile_statistics_microseconds'] = {
                percentile: describe_blocks([cell['timing'][percentile + '_ns'] / 1000 for cell in cells])
                for percentile in ('p50', 'p95', 'p99')}
        timing.append(row)
    return {'timing_and_scaling': timing, 'existing_paired_block_bootstrap_comparisons': comparisons,
            'load_by_seed_all_conditions_retained': load_rows, 'cells_with_reference_disagreement': disagreements,
            'timing_interpretation': 'Means/min/max of process-block percentiles, not pooled request percentiles. Existing paired bootstrap intervals are copied without recomputation.'}


def report_markdown(analysis):
    lines = ['# v0.2 evaluation synthesis', '', f"Status: **{analysis['status']}**.", '',
             'This is a compact-summary synthesis, not an independent raw-observation recomputation.', '']
    if analysis['errors']:
        lines += ['## Missing or invalid evidence', '']
        lines += ['- ' + canonical(error) for error in analysis['errors']]
        lines += ['', 'No complete-campaign conclusion may be drawn until these entries are resolved.', '']
    lines += ['## Policy and dataset evidence', '']
    for label in ('validity', 'netslab'):
        value = analysis['policy_and_datasets'].get(label)
        if value:
            lines.append(f"- {label}: {value.get('constructed_case_count')} constructed cases; status {value.get('status')}; "
                         f"gateway decision disagreements {len(value.get('full_gateway_decision_mismatches', []))}, "
                         f"reason disagreements {len(value.get('full_gateway_reason_mismatches', []))}, "
                         f"unhandled errors {len(value.get('unhandled_errors', []))}.")
    for label in ('census', 'panels'):
        value = analysis['policy_and_datasets'].get(label, {})
        for group_name, group in value.get('groups', {}).items():
            gate = group['overall'].get('trust_boundary', {})
            admission = gate.get('policy_block_required_admissions', {})
            lines.append(f"- {label}/{group_name}: {gate.get('cases')} case occurrences; "
                         f"{group.get('distinct_meaningful_configurations_union')} normalized meaningful configurations; "
                         f"gateway reference agreement {canonical(gate.get('decision_agreement'))}; "
                         f"required-block admissions {admission.get('numerator')}/{admission.get('denominator')}.")
            if group_name == 'false_alarm_probes':
                lines.append('  Benign disruptive admission (limitation, not safe-action success): ' + canonical(gate.get('benign_disruptive_admission')) + '.')
    lines += ['', 'Alternative thresholds are reported separately in analysis.json; all configured conditions are retained.', '',
              '## Local timing and scaling', '', 'Values below are means of block p50/p95 values in microseconds; they are not pooled request percentiles.', '',
              '| Dataset | Mode | Boundary/path | State | Method | Blocks | Mean block p50 (µs) | Mean block p95 (µs) |',
              '|---|---|---|---:|---|---:|---:|---:|']
    for row in analysis['performance']['timing_and_scaling']:
        if row['resource_only'] or row['mode'] == 'scaling' and row['method'] != 'trust_boundary':
            continue
        values = row['block_percentile_statistics_microseconds']
        path = row['boundary'] if row['mode'] == 'micro' else row['state_path'] + ('; large input' if row['large_input'] else '')
        lines.append(f"| {row['dataset']} | {row['mode']} | {path} | {row['state_size']} | {row['method']} | {row['blocks']} | {values['p50']['mean']:.3f} | {values['p95']['mean']:.3f} |")
    lines += ['', 'Existing paired process-block bootstrap intervals (B3−B0 and B3−B2), all scaling methods, separate resource runs and per-seed load outcomes are retained in analysis.json.', '',
              '## Offered load', '', '| Dataset | Method | Rate/s | Seed | Completed/offered | Overflow/offered | Censored/offered | Generator-limited |',
              '|---|---|---:|---:|---:|---:|---:|---|']
    for row in analysis['performance']['load_by_seed_all_conditions_retained']:
        fractions = row['all_offered_fractions']
        display = lambda key: f"{fractions[key]['numerator']}/{fractions[key]['denominator']}"
        lines.append(f"| {row['dataset']} | {row['method']} | {row['offered_per_second']} | {row['seed']} | {display('completed')} | {display('overflow')} | {display('right_censored')} | {row['generator_limited']} |")
    lines += ['', '## Interpretation limits', ''] + ['- ' + value for value in LIMITATIONS]
    lines += ['', '## Selection and provenance', '',
              f"Selected revised performance partitions: {len(analysis['selected_performance_runs'])}/18. Excluded directories: {len(analysis['excluded_runs'])}; all remain untouched.", '',
              'See analysis.json for the exact selected/excluded run index and manifest.json for SHA-256 hashes of every consumed compact summary, receipt, source snapshot and protocol file. Earlier complete performance, pilots, diagnostics and incomplete attempts are not pooled into final estimates.', '']
    return '\n'.join(lines)


def synthesize(results_root: Path, output: Path):
    reader = Reader(results_root)
    output.mkdir(parents=True, exist_ok=False)
    generator = {'path': 'scripts/summarize_evaluation_v02.py',
                 'sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    analysis = {'version': 'evaluation-summary/0.2.0', 'status': 'NOT_COMPLETE', 'errors': [],
                'policy_and_datasets': {}, 'sensitivity': {}, 'selected_performance_runs': [],
                'shared_performance_source_snapshot_sha256': None,
                'excluded_runs': [], 'limitations': LIMITATIONS}
    try:
        reader.bytes(results_root / 'monitor_revision_protocol/ADDENDUM.md')
        for kind, name in FIXED_RUNS.items():
            try:
                summary, receipt = verify_child_summary(reader, results_root / name, kind)
                if kind in ('validity', 'netslab'):
                    analysis['policy_and_datasets'][kind] = summary
                elif kind.startswith('sensitivity:'):
                    analysis['sensitivity'][kind] = compact_dataset_summary(summary)
                else:
                    analysis['policy_and_datasets'][kind] = compact_dataset_summary(summary)
                if kind == 'census':
                    for filename in ('dataset_audit.json', 'natural_panel_analysis.json', 'sampling_protocol.json'):
                        path = results_root / name / 'work' / filename
                        item = reader.json(path)
                        if receipt['output_sha256'].get(filename) != reader.digest(path):
                            raise SummaryError('census supplemental summary hash mismatch')
                        analysis['policy_and_datasets'][filename.removesuffix('.json')] = item if filename != 'natural_panel_analysis.json' else {
                            key: item[key] for key in ('overlap_by_label_and_size', 'eligible_release_poststratified_min_max_across_seeds', 'note')}
            except (OSError, ValueError, KeyError, TypeError) as exc:
                analysis['errors'].append({'run': name, 'error_type': type(exc).__name__,
                                           'reason': str(exc) if isinstance(exc, SummaryError) else 'missing or invalid compact artifact'})
        candidates = []
        for directory in sorted(results_root.iterdir()):
            if not directory.is_dir() or directory.resolve() == output.resolve() or directory.name in FIXED_RUNS.values():
                continue
            key = revision_partition(directory.name)
            if key is None:
                analysis['excluded_runs'].append({'run': directory.name, 'reason': 'not_a_predeclared_final_revision_performance_label'})
                continue
            try:
                verify_parent(reader, directory)
                candidates.append((key, directory))
            except (OSError, ValueError, KeyError, TypeError):
                analysis['excluded_runs'].append({'run': directory.name, 'reason': 'incomplete_or_invalid_execution_provenance'})
        selected, errors = select_unique_complete(candidates)
        analysis['errors'].extend(errors)
        partitions = []
        for key, directory in selected.items():
            try:
                partition = performance_partition(reader, directory, key)
                partitions.append(partition)
                analysis['selected_performance_runs'].append({'partition': list(key), 'run': directory.name,
                                                              'source_snapshot_sha256': partition['source_snapshot_sha256'],
                                                              'cells': expected_partitions()[key]})
            except (OSError, ValueError, KeyError, TypeError) as exc:
                analysis['errors'].append({'run': directory.name, 'error_type': type(exc).__name__,
                                           'reason': str(exc) if isinstance(exc, SummaryError) else 'invalid compact performance artifacts'})
        # A single frozen revision/design/workload is required for final pooling.
        for field in ('output_monitor_version', 'design_sha256', 'workload_manifest_sha256'):
            values = {canonical(part['plan_metadata'].get(field)) for part in partitions}
            if len(values) > 1:
                analysis['errors'].append({'reason': 'inconsistent_final_performance_provenance', 'field': field})
        analysis['performance'] = aggregate_performance(partitions)
        analysis['shared_performance_source_snapshot_sha256'] = require_shared_source_snapshot(
            part['source_snapshot_sha256'] for part in partitions)
        if not analysis['errors']:
            analysis['status'] = 'COMPLETE_WITH_REPORTED_FINDINGS'
    except (OSError, ValueError, KeyError, TypeError) as exc:
        analysis['errors'].append({'error_type': type(exc).__name__,
                                   'reason': str(exc) if isinstance(exc, SummaryError) else 'missing or invalid campaign artifact'})
        analysis.setdefault('performance', aggregate_performance([]))
    generator_unchanged = hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == generator['sha256']
    if not generator_unchanged:
        analysis['errors'].append({'reason': 'report_generator_changed_during_synthesis'})
        analysis['status'] = 'NOT_COMPLETE'
    analysis['verification_scope'] = 'Compact JSON/protocol bytes and recorded provenance only; raw observations not reread or independently reverified.'
    outputs = {'analysis.json': canonical(analysis) + '\n', 'REPORT.md': report_markdown(analysis)}
    for name, text in outputs.items():
        with (output / name).open('x', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
    manifest = {'version': analysis['version'], 'status': analysis['status'], 'consumed_files': reader.manifest,
                'generator': generator, 'generator_unchanged_during_synthesis': generator_unchanged,
                'output_sha256': {name: hashlib.sha256(text.encode('utf-8')).hexdigest() for name, text in outputs.items()},
                'verification_scope': analysis['verification_scope']}
    with (output / 'manifest.json').open('x', encoding='utf-8', newline='\n') as handle:
        handle.write(canonical(manifest) + '\n')
    return analysis


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results-root', type=Path, default=ROOT / 'results/evaluation_v0.2')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = synthesize(args.results_root.resolve(), args.output.resolve())
    print(canonical({'status': result['status'], 'errors': len(result['errors']),
                     'selected_performance_partitions': len(result['selected_performance_runs'])}))
    return 0 if result['status'].startswith('COMPLETE') else 2


if __name__ == '__main__':
    raise SystemExit(main())
