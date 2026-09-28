"""Streaming, additive v0.2 dataset evaluation; the v0.1 release is immutable.

Sampling protocol (5gnidd-keyed-rank/1): parse UTF-8-sig strict CSV; retain header
order except blank/Unnamed: index columns. SHA256 UTF-8 JSON array of the original
cell strings, ensure_ascii=True and separators=(',', ':'), identifies duplicates.
For seed s, key = ASCII '5gnidd-keyed-rank/1\\0' + s as unsigned 4-byte big-endian.
Rank = HMAC-SHA256(key, archive SHA256 raw 32 bytes + row SHA256 raw 32 bytes).
Order by unsigned rank, then 1-based parsed-row ordinal. Each seed/label keeps the
lowest 250 ranks; the first 25 and 100 are nested panels. No Python hash/random,
row-order inference about sessions, labels-as-features, or IP exports are used.

These observations are policy-conformance cases, not independent safety trials.
The source labels condition proposals; no learned detector is evaluated.
"""
from __future__ import annotations

from collections import Counter, OrderedDict, defaultdict
from contextlib import contextmanager
from copy import deepcopy
import csv
from datetime import UTC, datetime
from fractions import Fraction
import hashlib
import heapq
import hmac
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import sys
import time
from typing import Any, Iterable, Iterator
import zipfile

from .approval import StaticApprovalRegistry
from .audit import completeness, verify_record_checksum
from .baselines import contract_only, contract_rbac, direct_execution
from .engine import TrustBoundary
from .evaluation_reference import ReferencePolicy, canonical_digest
from .jsonio import strict_json_load, strict_json_loads
from .nidd_adapter import (ARCHIVE_SHA256, MAX_CSV_BYTES, MAX_ROWS, REQUIRED_COLUMNS,
                           SELECTED_LABELS, NiddValidationError, _measurements, _strict_rows)
from .nidd_cases import (_case, _proposal, _validate_context, build_cases)
from .provenance import sha256_file, source_manifest

ROOT = Path(__file__).resolve().parents[2]
SYSTEMS = ('direct', 'contract', 'contract_rbac', 'trust_boundary')
EXPECTED_COUNTS = {'Benign': 477716, 'ICMPFlood': 1154, 'SYNFlood': 8394, 'UDPFlood': 246429}
SAMPLING_SPEC = {
    'version': '5gnidd-keyed-rank/1',
    'row_encoding': "UTF-8 json.dumps(header-ordered original cell strings excluding blank and Unnamed: headers, ensure_ascii=True, separators=(',', ':'))",
    'row_identity': 'SHA256(row_encoding); first occurrence retained before numeric eligibility checks',
    'seed_key': "ASCII 5gnidd-keyed-rank/1 followed by NUL followed by unsigned 4-byte big-endian seed",
    'rank': 'HMAC-SHA256(seed_key, bytes.fromhex(archive_sha256) + row_sha256_bytes)',
    'tie_break': 'ascending parsed-row ordinal (1-based)',
    'seeds': list(range(20)), 'largest_per_label': 250, 'nested_prefixes': [25, 100, 250],
    'labels': list(SELECTED_LABELS),
    'independence': 'overlapping panels; no independent-trial confidence intervals',
}
CLAIM_LIMIT = ('Offline policy conformance, not incident truth, mitigation effectiveness, '
               'session generalization, network capacity or production O-RAN safety. '
               'All control identities, targets, authority and state are simulated.')


def encoded_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('utf-8')


def iter_eligible_records(archive_path: Path, audit: dict, *, expected_sha256: str = ARCHIVE_SHA256,
                          checkpoint=None) -> Iterator[tuple[dict, bytes]]:
    """Yield sanitized eligible contexts; reconcile exact v0.1 parsing/exclusions.

    The caller MUST exhaust the iterator for CRC, malformed-row and final hash
    validation. A partial output cannot be a completed census. Custom hashes are
    for tiny unit fixtures only; production CLIs have no checksum override.
    """
    path = Path(archive_path)
    if len(expected_sha256) != 64 or any(c not in '0123456789abcdef' for c in expected_sha256):
        raise NiddValidationError('invalid expected archive digest')
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 100 * 1024**2:
        raise NiddValidationError('archive must be regular, nonsymlink and at most 100 MiB')
    if sha256_file(path) != expected_sha256:
        raise NiddValidationError('archive SHA-256 mismatch')
    counts = {name: Counter() for name in ('attack_counts', 'binary_label_counts', 'missing_counts',
                                          'duplicate_counts', 'eligible_unique_counts', 'selection_exclusions')}
    audit.update(row_count=0, malformed_rows=0, invalid_measurement_rows=0)
    seen: set[bytes] = set()
    with zipfile.ZipFile(path) as archive:
        members = [m for m in archive.infolist() if not m.is_dir()]
        if len(members) != 1:
            raise NiddValidationError('expected exactly one CSV member')
        member = members[0]
        name = PurePosixPath(member.filename)
        if (name.is_absolute() or '..' in name.parts or '\\' in member.filename or ':' in member.filename
                or name.suffix.lower() != '.csv' or stat.S_ISLNK(member.external_attr >> 16)
                or member.flag_bits & 1 or not 0 < member.file_size <= MAX_CSV_BYTES):
            raise NiddValidationError('unsafe or unsupported CSV member')
        with archive.open(member) as binary, io.TextIOWrapper(binary, encoding='utf-8-sig', newline='') as text:
            reader = csv.DictReader(text, strict=True)
            try:
                columns = reader.fieldnames or []
            except csv.Error as exc:
                raise NiddValidationError('malformed CSV header') from exc
            if len(columns) != len(set(columns)) or not REQUIRED_COLUMNS <= set(columns):
                raise NiddValidationError('missing required or duplicate headers')
            audit['columns'] = columns
            content_columns = [c for c in columns if c and not c.startswith('Unnamed:')]
            for ordinal, row in enumerate(_strict_rows(reader), 1):
                audit['row_count'] = ordinal
                if ordinal > MAX_ROWS:
                    raise NiddValidationError('CSV row bound exceeded')
                if checkpoint and ordinal % 10000 == 0:
                    checkpoint(ordinal)
                if None in row or any(v is None for v in row.values()):
                    audit['malformed_rows'] += 1
                    continue
                for column, value in row.items():
                    if not value.strip() or value.strip().lower() in {'nan', 'null', 'none'}:
                        counts['missing_counts'][column] += 1
                label, binary_label = row['Attack Type'].strip(), row['Label'].strip()
                if not label or not binary_label:
                    raise NiddValidationError('missing incident label')
                counts['attack_counts'][label] += 1
                counts['binary_label_counts'][binary_label] += 1
                if (label == 'Benign' and binary_label != 'Benign') or (label != 'Benign' and binary_label != 'Malicious'):
                    raise NiddValidationError('inconsistent binary/attack labels')
                raw = json.dumps([row[c] for c in content_columns], ensure_ascii=True, separators=(',', ':')).encode('utf-8')
                digest = hashlib.sha256(raw).digest()
                duplicate = digest in seen
                seen.add(digest)
                if duplicate:
                    counts['duplicate_counts'][label] += 1
                try:
                    duration, packets, rate = _measurements(row)
                except NiddValidationError:
                    audit['invalid_measurement_rows'] += 1
                    if label in SELECTED_LABELS:
                        counts['selection_exclusions'][f'{label}:invalid_measurements'] += 1
                    continue
                if label not in SELECTED_LABELS:
                    counts['selection_exclusions'][f'{label}:outside_predeclared_flood_comparison'] += 1
                    continue
                if duplicate:
                    counts['selection_exclusions'][f'{label}:duplicate_record'] += 1
                    continue
                if label != 'Benign' and (rate is None or rate <= 0):
                    counts['selection_exclusions'][f'{label}:nonpositive_or_undefined_packet_rate'] += 1
                    continue
                counts['eligible_unique_counts'][label] += 1
                record_id = hashlib.sha256(f'{expected_sha256}:{member.filename}:{ordinal}'.encode()).hexdigest()[:32]
                yield ({'record_id': record_id, 'source_row_number': ordinal, 'attack_type': label,
                        'duration_seconds': duration, 'total_packets': packets, 'packets_per_second': rate}, digest)
    audit.update({key: dict(sorted(value.items())) for key, value in counts.items()})
    audit['duplicate_rows'] = sum(counts['duplicate_counts'].values())
    if audit['malformed_rows']:
        raise NiddValidationError('malformed rows present; partial census is invalid')
    if sha256_file(path) != expected_sha256:
        raise NiddValidationError('archive changed during streaming')


def raw_reduction(pps: float, budget: int = 1000) -> int:
    if type(budget) is not int or budget <= 0 or not math.isfinite(pps) or pps <= 0:
        raise ValueError('positive finite packet rate and integer budget required')
    return 1 if pps <= budget else max(1, math.ceil(100 * (1 - budget / pps)))


def natural_case(context: dict, budget: int = 1000) -> dict:
    context = _validate_context(context)
    reduction = None if context['attack_type'] == 'Benign' else raw_reduction(context['packets_per_second'], budget)
    case = _case(context, _proposal(context, reduction=reduction), group='record_proposals',
                 category='benign_notification' if reduction is None else 'record_derived_mitigation',
                 raw_reduction=reduction)
    _budget_context(case, budget, reduction)
    return case


def _budget_context(case: dict, budget: int, raw: int | None) -> None:
    generation = case['source_context']['proposal_generation']
    generation.update(packet_budget_per_second=budget,
                      formula=f'max(1, ceil(100 * (1 - {budget} / packets_per_second)))',
                      record_derived_reduction_percent=raw,
                      proposed_reduction_percent=case['proposal']['parameters'].get('reduction_percent'))
    case['suite_version'] = '5gnidd-evaluation/0.2.0'
    case['approval_registry'] = {}


def make_nidd_groups(context: dict, budget: int = 1000) -> dict[str, list[dict]]:
    """Keep the original groups and 80% conformance clipping, even in sensitivity.

    Policy-bound variation must not move proposals to suit the new policy.
    Only the separately named packet-budget condition changes source-derived
    proposal values. The fixed 95% violation and 30% false-alarm probes stay fixed.
    """
    context = _validate_context(context)
    groups = build_cases([context])
    raw = None if context['attack_type'] == 'Benign' else raw_reduction(context['packets_per_second'], budget)
    for group, cases in groups.items():
        for case in cases:
            if raw is not None:
                if group == 'record_proposals':
                    case['proposal']['parameters']['reduction_percent'] = raw
                elif case['category'] != 'parameter_range':
                    case['proposal']['parameters']['reduction_percent'] = min(80, raw)
                if case['active_actions']:
                    case['active_actions'][0]['parameters']['reduction_percent'] = 60 if min(80, raw) != 60 else 30
            _budget_context(case, budget, raw)
    return groups


def attach_reference(case: dict, reference: ReferencePolicy) -> dict:
    result = deepcopy(case)
    expected = reference.evaluate(result)
    result.update(expected_reference=expected, expected_decision=expected['decision'],
                  expected_reasons=expected['reasons'],
                  expected_reason=expected['reasons'][0] if expected['reasons'] else None)
    # Original single-rule annotations are not a substitute for this condition's
    # independent expected outcome (e.g. precedence changes at a 60% bound).
    if 'policy_under_test' in result:
        result['original_fixture_policy_under_test'] = result.pop('policy_under_test')
    return result


class EvaluatorBundle:
    """One invocation per comparator, with immutable per-registry gate instances."""
    def __init__(self, policy: dict | None = None):
        self.policy = deepcopy(policy or strict_json_load(ROOT / 'configs/paper_policy.json', maximum_bytes=1024**2))
        self._gates: OrderedDict[str, TrustBoundary] = OrderedDict()

    def evaluate(self, case: dict) -> dict:
        registry = case.get('approval_registry', {})
        key = canonical_digest(registry)
        if key not in self._gates:
            self._gates[key] = TrustBoundary(self.policy, approval_verifier=StaticApprovalRegistry(registry))
            if len(self._gates) > 64:
                self._gates.popitem(last=False)
        gate = self._gates[key]
        self._gates.move_to_end(key)
        kwargs = {'policy': self.policy, 'authenticated_principal': case.get('authenticated_principal')}
        proposal = case['proposal']
        results = [direct_execution(proposal), contract_only(proposal), contract_rbac(proposal, **kwargs),
                   gate.evaluate(proposal, case.get('active_actions', []),
                                 authenticated_principal=case.get('authenticated_principal'),
                                 as_of=datetime.fromisoformat(case['evaluation_time'].replace('Z', '+00:00')))]
        return {name: {'decision': result.decision.value, 'reasons': list(result.reason_codes),
                       'policy_ids': list(result.policy_ids),
                       'audit_sha256': result.audit_record.get('record_sha256') if result.audit_record else None,
                       'audit_complete': completeness(result.audit_record, self.policy['audit_required_fields']) == 1,
                       'audit_checksum_valid': verify_record_checksum(result.audit_record) if result.audit_record else None}
                for name, result in zip(SYSTEMS, results)}


def rate(numerator: int, denominator: int) -> dict:
    return {'numerator': numerator, 'denominator': denominator,
            'rate': numerator / denominator if denominator else None}


def poststratified_rate(class_metrics: dict[str, dict], class_sample_sizes: dict[str, int],
                        populations: dict[str, int]) -> dict:
    """Ratio of release-weighted numerator/denominator fractions, not mean ratios.

    Exact rational terms make the estimator reproducible without treating its
    estimated release counts as observed counts. Zero conditional denominators
    in a class contribute zero, rather than changing that class's weight.
    """
    if set(class_metrics) != set(class_sample_sizes) or set(class_metrics) != set(populations):
        raise ValueError('poststratification requires every declared class')
    numerator, denominator = Fraction(0), Fraction(0)
    terms = {}
    for label, value in class_metrics.items():
        n, population = class_sample_sizes[label], populations[label]
        if type(n) is not int or n <= 0 or type(population) is not int or population <= 0:
            raise ValueError('positive integer sample and population counts required')
        a, b = value['numerator'], value['denominator']
        if type(a) is not int or type(b) is not int or not 0 <= a <= b <= n:
            raise ValueError('invalid conditional metric counts')
        numerator += Fraction(population * a, n)
        denominator += Fraction(population * b, n)
        terms[label] = {'sample_numerator': a, 'sample_denominator': b, 'sample_records': n,
                        'eligible_release_records': population}
    return {'rate': float(numerator / denominator) if denominator else None,
            'estimated_release_numerator_exact': {'numerator': numerator.numerator, 'denominator': numerator.denominator},
            'estimated_release_denominator_exact': {'numerator': denominator.numerator, 'denominator': denominator.denominator},
            'class_terms': terms,
            'formula': 'sum_l population_l*(sample_numerator_l/sample_records_l) / sum_l population_l*(sample_denominator_l/sample_records_l)'}


class Metrics:
    """Exact paired-case counts. Zero denominators are null, never perfect scores."""
    def __init__(self):
        self.cells: dict[tuple[str, str, str], Counter] = defaultdict(Counter)
        self.configurations: dict[tuple[str, str], set[str]] = defaultdict(set)

    def add(self, case: dict, outcomes: dict, *, group: str | None = None, label: str | None = None):
        from .evaluation_cases import semantic_hash
        group = group or case.get('experiment_group', 'generated_controls')
        label = label or case.get('source_context', {}).get('observed', {}).get('attack_type', case.get('category', 'unspecified'))
        self.configurations[(group, label)].add(semantic_hash(case))
        expected = case['expected_reference']
        false_alarm = group == 'false_alarm_probes'
        for system, observed in outcomes.items():
            c = self.cells[(group, label, system)]
            c['n'] += 1
            c['expected_' + expected['decision']] += 1
            c['observed_' + observed['decision']] += 1
            c['agreement'] += observed['decision'] == expected['decision']
            c['block_required'] += expected['decision'] != 'ALLOW'
            c['incorrect_admissions'] += expected['decision'] != 'ALLOW' and observed['decision'] == 'ALLOW'
            c['incorrect_rejections'] += expected['decision'] == 'ALLOW' and observed['decision'] != 'ALLOW'
            c['allow_required'] += expected['decision'] == 'ALLOW'
            c['compliant_accepted'] += expected['decision'] == 'ALLOW' and observed['decision'] == 'ALLOW'
            c['correct_denial'] += expected['decision'] == 'DENY' and observed['decision'] == 'DENY'
            c['correct_escalation'] += expected['decision'] == 'ESCALATE' and observed['decision'] == 'ESCALATE'
            c['false_alarm_n'] += false_alarm
            c['false_alarm_admitted'] += false_alarm and observed['decision'] == 'ALLOW'
            c['audit_complete'] += observed['audit_complete']
            c['audit_checksum_valid'] += observed['audit_checksum_valid'] is True
            reason_ok = (set(observed['reasons']) == set(expected['reasons'])
                         if expected['reason_comparison'] == 'exact_set' else bool(observed['reasons']))
            c['reason_agreement'] += reason_ok and observed['decision'] == expected['decision']

    @staticmethod
    def describe(c: Counter, *, false_alarm: bool = False) -> dict:
        return {'cases': c['n'], 'expected_decisions': {d: c['expected_' + d] for d in ('ALLOW', 'DENY', 'ESCALATE')},
                'observed_decisions': {d: c['observed_' + d] for d in ('ALLOW', 'DENY', 'ESCALATE')},
                'decision_agreement': rate(c['agreement'], c['n']),
                'policy_block_required_admissions': rate(c['incorrect_admissions'], c['block_required']),
                'incorrect_rejections': rate(c['incorrect_rejections'], c['allow_required']),
                'compliant_action_acceptance': None if false_alarm else rate(c['compliant_accepted'], c['allow_required']),
                'correct_denials': rate(c['correct_denial'], c['expected_DENY']),
                'correct_escalations': rate(c['correct_escalation'], c['expected_ESCALATE']),
                'benign_disruptive_admission': rate(c['false_alarm_admitted'], c['false_alarm_n']),
                'reference_reason_agreement': rate(c['reason_agreement'], c['n']),
                'complete_audit_fields': rate(c['audit_complete'], c['n']),
                'valid_audit_checksum': rate(c['audit_checksum_valid'], c['n'])}

    def summary(self) -> dict:
        groups: dict[str, dict] = {}
        for (group, label, system), counts in sorted(self.cells.items()):
            target = groups.setdefault(group, {'by_label': {}, 'overall': {}, 'distinct_meaningful_configurations': {}})
            target['by_label'].setdefault(label, {})[system] = self.describe(counts, false_alarm=group == 'false_alarm_probes')
        for group, target in groups.items():
            for system in SYSTEMS:
                combined = Counter()
                for (g, _, s), counts in self.cells.items():
                    if g == group and s == system:
                        combined.update(counts)
                target['overall'][system] = self.describe(combined, false_alarm=group == 'false_alarm_probes')
            target['distinct_meaningful_configurations'] = {
                label: len(configs) for (g, label), configs in sorted(self.configurations.items()) if g == group}
            target['distinct_meaningful_configurations_union'] = len(set().union(
                *(configs for (g, _), configs in self.configurations.items() if g == group)))
        gate_counts = Counter()
        for (_, _, system), counts in self.cells.items():
            if system == 'trust_boundary':
                gate_counts.update(counts)
        findings = {'decision_mismatches': gate_counts['n'] - gate_counts['agreement'],
                    'reference_reason_mismatches': gate_counts['n'] - gate_counts['reason_agreement'],
                    'incomplete_audits': gate_counts['n'] - gate_counts['audit_complete'],
                    'invalid_audit_checksums': gate_counts['n'] - gate_counts['audit_checksum_valid']}
        return {'claim_limit': CLAIM_LIMIT, 'groups': groups, 'trust_boundary_findings': findings,
                'scientific_status': 'COMPLETED_WITH_FINDINGS' if any(findings.values()) else 'COMPLETED',
                'denominator_note': 'Exact constructed-case denominators; null means no applicable cases. False-alarm probes are excluded from compliant-action acceptance. No independence or safety-probability claim.',
                'reason_note': 'Comparator reasons are measured against full-policy reference reasons, not against comparator-specific specifications.'}


class SeedPanels:
    def __init__(self, seeds: Iterable[int] = range(20), capacity: int = 250, archive_sha256: str = ARCHIVE_SHA256):
        self.seeds = tuple(seeds)
        if not self.seeds or len(set(self.seeds)) != len(self.seeds) or any(type(s) is not int or not 0 <= s < 2**32 for s in self.seeds):
            raise ValueError('unique unsigned 32-bit seeds required')
        if type(capacity) is not int or not 1 <= capacity <= 250:
            raise ValueError('capacity must be 1..250')
        self.capacity = capacity
        self.archive = bytes.fromhex(archive_sha256)
        self.keys = {s: b'5gnidd-keyed-rank/1\0' + s.to_bytes(4, 'big') for s in self.seeds}
        self.heaps = {(s, label): [] for s in self.seeds for label in SELECTED_LABELS}

    def add(self, context: dict, row_digest: bytes, evaluated: dict):
        for seed in self.seeds:
            rank = hmac.digest(self.keys[seed], self.archive + row_digest, 'sha256')
            item = (-int.from_bytes(rank, 'big'), -context['source_row_number'],
                    {'context': context, 'row_sha256': row_digest.hex(), 'rank_sha256': rank.hex(), **evaluated})
            heap = self.heaps[(seed, context['attack_type'])]
            if len(heap) < self.capacity:
                heapq.heappush(heap, item)
            elif item[:2] > heap[0][:2]:
                heapq.heapreplace(heap, item)

    def export(self, *, require_full: bool = True) -> dict:
        if require_full and any(len(heap) != self.capacity for heap in self.heaps.values()):
            raise ValueError('insufficient records for a complete panel')
        return {'format': '5gnidd-panels/0.2.0', 'sampling_spec': SAMPLING_SPEC,
                'sampling_spec_sha256': canonical_digest(SAMPLING_SPEC),
                'archive_sha256': self.archive.hex(), 'capacity': self.capacity,
                'seeds': {str(seed): {label: [item[2] for item in sorted(self.heaps[(seed, label)], key=lambda x: (-x[0], -x[1]))]
                                     for label in SELECTED_LABELS} for seed in self.seeds}}


def panel_analysis(panels: dict) -> dict:
    """Descriptive natural metrics re-use census outcomes, not new engine calls."""
    by_seed, overlap = {}, {}
    extrema: dict[tuple[int, str, str], list[float]] = defaultdict(list)
    for seed, classes in panels['seeds'].items():
        by_seed[seed] = {}
        for n in (25, 100, 250):
            if n > panels['capacity']:
                continue
            metrics = Metrics()
            per_label = {}
            for label, entries in classes.items():
                for entry in entries[:n]:
                    case = natural_case(entry['context'])
                    case['expected_reference'] = entry['expected_reference']
                    metrics.add(case, entry['outcomes'])
                per_label[label] = len(entries[:n])
            summary = metrics.summary()
            cells = summary['groups']['record_proposals']['by_label']
            weighted = {}
            for system in SYSTEMS:
                weighted[system] = {}
                for metric in ('decision_agreement', 'policy_block_required_admissions', 'incorrect_rejections', 'compliant_action_acceptance'):
                    applicable = [(label, cells[label][system][metric]['rate']) for label in SELECTED_LABELS
                                  if cells[label][system][metric]['rate'] is not None]
                    # A conditional rate cannot silently discard absent class
                    # denominators. Report which labels enter each weighted mean.
                    macro = sum(v for _, v in applicable) / len(applicable) if applicable else None
                    denominator = sum(EXPECTED_COUNTS[label] for label, _ in applicable)
                    release = sum(EXPECTED_COUNTS[label] * v for label, v in applicable) / denominator if denominator else None
                    standardized = poststratified_rate({label: cells[label][system][metric] for label in SELECTED_LABELS},
                                                        per_label, EXPECTED_COUNTS)
                    weighted[system][metric] = {'macro_conditional_class_mean': macro,
                                               'eligible_release_poststratified': standardized,
                                               'descriptive_population_weighted_conditional_class_mean': release,
                                               'applicable_labels': [label for label, _ in applicable],
                                               'weight_denominator_records': denominator}
                    if standardized['rate'] is not None:
                        extrema[(n, system, metric)].append(standardized['rate'])
            by_seed[seed][str(n)] = {'sample_counts': per_label, 'summary': summary, 'weighted_class_rates': weighted}
    for label in SELECTED_LABELS:
        overlap[label] = {}
        for n in (25, 100, 250):
            if n > panels['capacity']:
                continue
            sets = {seed: {entry['context']['record_id'] for entry in classes[label][:n]}
                    for seed, classes in panels['seeds'].items()}
            pairs = [{'seed_a': a, 'seed_b': b, 'intersection': len(sets[a] & sets[b]),
                      'union': len(sets[a] | sets[b]), 'jaccard': len(sets[a] & sets[b]) / len(sets[a] | sets[b])}
                     for index, a in enumerate(sets) for b in list(sets)[index + 1:]]
            overlap[label][str(n)] = {'unique_record_union': len(set().union(*sets.values())),
                                      'panel_record_occurrences': sum(map(len, sets.values())), 'pairwise': pairs}
    return {'by_seed_and_size': by_seed, 'overlap_by_label_and_size': overlap,
            'eligible_release_poststratified_min_max_across_seeds': [
                {'size': n, 'system': s, 'metric': m, 'minimum': min(v), 'maximum': max(v)}
                for (n, s, m), v in sorted(extrema.items())],
            'note': 'No confidence intervals: panels overlap and outcomes are reused from the census. Primary release weighting is the ratio of poststratified numerator and denominator fractions. Macro and population-weighted means of class-conditional rates are separately labeled descriptive quantities, not the release-wide conditional rate.'}


def worker_rss_bytes() -> int:
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize', 'QuotaPeakPagedPoolUsage',
                  'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage', 'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage')]
        counter = Counters()
        counter.cb = ctypes.sizeof(counter)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        psapi = ctypes.WinDLL('psapi', use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counter), counter.cb):
            raise RuntimeError('RSS monitoring unavailable')
        return counter.PeakWorkingSetSize
    import resource
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == 'darwin' else value * 1024)


class EvaluationRun:
    """Exclusive files, bounded output, before/after provenance, incomplete failures.

    Polling is a cooperative secondary guard. Large production runs additionally
    run under the root supervisor's OS job/wall/directory bounds.
    """
    def __init__(self, output: Path, stage: str, inputs: dict[str, Path], *, large: bool = True):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=False)
        self.stage, self.inputs = stage, inputs
        self.started = time.monotonic()
        self.output_bytes = 0
        self.progress = {}
        self.sources_before = {}
        self.input_before = {}
        self.limit = 5 * 1024**3 - 1024**2
        try:
            self.sources_before = source_manifest(ROOT)
            self.input_before = {key: sha256_file(path) for key, path in inputs.items()}
            self.write_json('STARTED.json', {'status': 'INCOMPLETE', 'stage': stage, 'started_utc': datetime.now(UTC).isoformat(),
                                           'input_sha256': self.input_before, 'sampling_spec_sha256': canonical_digest(SAMPLING_SPEC),
                                           'source_files': self.sources_before})
            self.check()
            if large and shutil.disk_usage(self.output).free < 10 * 1024**3:
                raise RuntimeError('preflight requires 10 GiB free disk')
        except BaseException as exc:
            self.finish(False, error_type=type(exc).__name__)
            raise

    def check(self):
        if time.monotonic() - self.started > 3600:
            raise RuntimeError('one-hour worker wall bound exceeded')
        if worker_rss_bytes() > 2 * 1024**3:
            raise RuntimeError('2 GiB worker RSS bound exceeded')
        if self.output_bytes > self.limit:
            raise RuntimeError('5 GiB worker output bound exceeded')

    def _write(self, handle, value):
        payload = encoded_json(value) + b'\n'
        if self.output_bytes + len(payload) > self.limit:
            raise RuntimeError('5 GiB output bound would be exceeded')
        handle.write(payload)
        self.output_bytes += len(payload)

    def write_json(self, name: str, value):
        with (self.output / name).open('xb') as handle:
            self._write(handle, value)

    @contextmanager
    def jsonl(self, name: str):
        with (self.output / name).open('xb', buffering=1024**2) as handle:
            yield lambda value: self._write(handle, value)

    def checkpoint(self, **progress):
        self.progress.update(progress)
        self.check()
        print(json.dumps({'stage': self.stage, **self.progress}, sort_keys=True), flush=True)

    def finish(self, complete: bool, **extra):
        try:
            sources_after = source_manifest(ROOT)
            input_after = {key: sha256_file(path) if path.is_file() else None for key, path in self.inputs.items()}
        except OSError:
            sources_after, input_after = {}, {}
            complete = False
        try:
            peak_rss = worker_rss_bytes()
        except (OSError, RuntimeError, ImportError):
            peak_rss = None
            complete = False
        unchanged = self.sources_before == sources_after and self.input_before == input_after
        receipt = {'status': 'COMPLETE' if complete and unchanged else 'INCOMPLETE', 'stage': self.stage,
                   'input_sha256_before': self.input_before, 'input_sha256_after': input_after,
                   'source_files_before': self.sources_before, 'source_files_after': sources_after,
                   'inputs_and_source_unchanged': unchanged, 'progress': self.progress,
                   'wall_seconds': time.monotonic() - self.started, 'peak_rss_bytes': peak_rss,
                   'python_version': platform.python_version(), 'operating_system': platform.system(),
                   'output_sha256': {p.name: sha256_file(p) for p in sorted(self.output.iterdir()) if p.is_file()},
                   'claim_limit': CLAIM_LIMIT, **extra}
        # Reserved receipt allowance makes a resource-limit failure reportable.
        with (self.output / 'RUN.json').open('xb') as handle:
            handle.write(encoded_json(receipt) + b'\n')
        if complete and not unchanged:
            raise RuntimeError('source/input changed during run; output marked INCOMPLETE')


def load_panels(path: Path) -> dict:
    panels = strict_json_load(path, maximum_bytes=80 * 1024**2)
    if (panels.get('format') != '5gnidd-panels/0.2.0' or panels.get('archive_sha256') != ARCHIVE_SHA256
            or panels.get('sampling_spec') != SAMPLING_SPEC
            or panels.get('sampling_spec_sha256') != canonical_digest(SAMPLING_SPEC)
            or panels.get('capacity') != 250 or set(panels.get('seeds', {})) != {str(s) for s in range(20)}):
        raise ValueError('panel metadata does not match the frozen selection design')
    for seed, classes in panels['seeds'].items():
        if set(classes) != set(SELECTED_LABELS):
            raise ValueError('panel labels mismatch')
        ids = set()
        for label, entries in classes.items():
            if len(entries) != 250:
                raise ValueError('panel must have exactly 250 records per class')
            previous = None
            for entry in entries:
                context = _validate_context(entry['context'])
                if context['attack_type'] != label or context['record_id'] in ids:
                    raise ValueError('duplicate or mislabeled selected context')
                ids.add(context['record_id'])
                if entry.get('proposal_sha256') != canonical_digest(natural_case(context)['proposal']):
                    raise ValueError('cached census proposal digest does not bind the selected context')
                row_digest = bytes.fromhex(entry['row_sha256'])
                expected_rank = hmac.digest(b'5gnidd-keyed-rank/1\0' + int(seed).to_bytes(4, 'big'),
                                            bytes.fromhex(ARCHIVE_SHA256) + row_digest, 'sha256').hex()
                rank = (entry['rank_sha256'], context['source_row_number'])
                if len(row_digest) != 32 or expected_rank != rank[0] or previous is not None and rank <= previous:
                    raise ValueError('invalid or unordered panel rank')
                previous = rank
    return panels


def verify_completed_input(directory: Path, required_names: Iterable[str]) -> dict:
    """Verify a full, reconciled and supervised census before consuming selections."""
    receipt = strict_json_load(directory / 'RUN.json', maximum_bytes=4 * 1024**2)
    progress = receipt.get('progress', {})
    if (receipt.get('status') != 'COMPLETE' or receipt.get('inputs_and_source_unchanged') is not True
            or receipt.get('stage') != 'stage2a_5gnidd_census' or receipt.get('audit_reconciled') is not True
            or progress.get('evaluated_records') != 733693 or progress.get('source_rows') != 1215890
            or progress.get('comparator_decisions') != 2934772
            or receipt.get('input_sha256_before', {}).get('archive') != ARCHIVE_SHA256
            or receipt.get('input_sha256_after', {}).get('archive') != ARCHIVE_SHA256):
        raise ValueError('upstream input is not a complete reconciled full-release census')
    for name in required_names:
        if receipt.get('output_sha256', {}).get(name) != sha256_file(directory / name):
            raise ValueError('upstream artifact hash mismatch')
    verify_supervisor_receipt(directory.parent / 'COMPLETE.json')
    return receipt


def verify_supervisor_receipt(path: Path) -> None:
    supervisor = strict_json_load(path, maximum_bytes=4 * 1024**2)
    if (supervisor.get('status') != 'COMPLETE' or supervisor.get('source_unchanged') is not True
            or supervisor.get('baseline_after', {}).get('status') != 'pass'):
        raise ValueError('upstream supervised execution/provenance receipt is not complete')


def verify_netslab_input(directory: Path) -> dict[str, Path]:
    """Accept only the complete frozen generated suite, not a favorable subset."""
    receipt_path = directory / 'COMPLETE.json'
    receipt = strict_json_load(receipt_path, maximum_bytes=4 * 1024**2)
    if (receipt.get('status') not in ('COMPLETED', 'COMPLETED_WITH_FINDINGS')
            or receipt.get('mode') != 'netslab' or receipt.get('constructed_case_count') != 20000):
        raise ValueError('NetsLab input must be a complete 20,000-case generated campaign')
    names = ('cases.jsonl', 'decisions.jsonl', 'summary.json', 'REPORT.md')
    for name in names:
        path = directory / name
        if path.is_symlink() or receipt.get('files', {}).get(name, {}).get('sha256') != sha256_file(path):
            raise ValueError('NetsLab upstream artifact hash mismatch')
    supervisor_path = directory.parent / 'COMPLETE.json'
    verify_supervisor_receipt(supervisor_path)
    return {'cases': directory / 'cases.jsonl', 'generated_suite_receipt': receipt_path,
            'supervisor_receipt': supervisor_path,
            **{f'upstream_{name}': directory / name for name in names[1:]}}


def run_census(archive: Path, output: Path, *, pilot_records: int | None = None) -> None:
    if pilot_records is not None and (type(pilot_records) is not int or not 1 <= pilot_records <= 1000):
        raise ValueError('instrumentation pilot_records must be 1..1000')
    historical = ROOT / 'results/5gnidd_v0.1_verified/dataset_audit.json'
    run = EvaluationRun(output, 'stage2a_5gnidd_census_pilot' if pilot_records else 'stage2a_5gnidd_census',
                        {'archive': archive, 'historical_audit': historical}, large=pilot_records is None)
    try:
        expected_audit = strict_json_load(historical, maximum_bytes=2 * 1024**2)['audit']
        reference, evaluator, metrics, panels, audit = ReferencePolicy(), EvaluatorBundle(), Metrics(), SeedPanels(), {}
        n = 0
        records = iter_eligible_records(archive, audit, checkpoint=lambda rows: run.checkpoint(source_rows=rows, evaluated_records=n))
        with run.jsonl('census_decisions.jsonl') as write:
            for context, row_digest in records:
                case = attach_reference(natural_case(context), reference)
                outcomes = evaluator.evaluate(case)
                record = {'context': context, 'row_sha256': row_digest.hex(),
                          'proposal_parameters': case['proposal']['parameters'], 'proposal_sha256': canonical_digest(case['proposal']),
                          'expected_reference': case['expected_reference'], 'outcomes': outcomes}
                write(record)
                metrics.add(case, outcomes)
                panels.add(context, row_digest, {'proposal_sha256': record['proposal_sha256'],
                                                'expected_reference': case['expected_reference'], 'outcomes': outcomes})
                n += 1
                if n % 1000 == 0:
                    run.check()
                if pilot_records is not None and n == pilot_records:
                    break
        records.close()
        if pilot_records is not None:
            if n != pilot_records:
                raise ValueError('insufficient eligible records for the instrumentation pilot')
            run.write_json('summary.json', {'status': 'PILOT_NOT_CONFIRMATORY', 'instrumentation_records': n,
                                           'partial_csv_not_fully_crc_validated_or_audit_reconciled': True,
                                           'metrics': metrics.summary(),
                                           'not_usable_as': 'census, selection panel, sensitivity or scientific effect evidence'})
            run.checkpoint(source_rows=audit['row_count'], evaluated_records=n, comparator_decisions=n * 4)
            run.finish(True, scientific_status='PILOT_NOT_CONFIRMATORY', audit_reconciled=False)
            return
        if audit != expected_audit or audit['eligible_unique_counts'] != EXPECTED_COUNTS or n != 733693:
            run.write_json('unreconciled_audit.json', audit)
            raise ValueError('full source audit did not exactly reconcile with immutable historical audit')
        selected = panels.export()
        run.write_json('dataset_audit.json', {'audit': audit, 'archive_sha256': ARCHIVE_SHA256})
        run.write_json('sampling_protocol.json', SAMPLING_SPEC)
        run.write_json('panels.json', selected)
        run.write_json('natural_panel_analysis.json', panel_analysis(selected))
        run.write_json('summary.json', metrics.summary())
        run.checkpoint(source_rows=audit['row_count'], evaluated_records=n, comparator_decisions=n * 4)
        run.finish(True, audit_reconciled=True, comparator_invocations_per_record=4)
    except BaseException as exc:
        if not (output / 'RUN.json').exists():
            run.finish(False, error_type=type(exc).__name__)
        raise


def run_panels(census_output: Path, output: Path) -> None:
    verify_completed_input(census_output, ['panels.json', 'dataset_audit.json'])
    panel_path = census_output / 'panels.json'
    run = EvaluationRun(output, 'stage2b_5gnidd_conformance', {'panels': panel_path, 'census_receipt': census_output / 'RUN.json',
                                                           'census_supervisor_receipt': census_output.parent / 'COMPLETE.json'})
    try:
        panels, reference, evaluator = load_panels(panel_path), ReferencePolicy(), EvaluatorBundle()
        overall, per_seed, total = Metrics(), {}, 0
        for seed, classes in panels['seeds'].items():
            metrics, group_counts = Metrics(), Counter()
            for group in ('conformance', 'false_alarm_probes'):
                with run.jsonl(f'cases_seed_{int(seed):02d}_{group}.jsonl') as write_case, run.jsonl(f'decisions_seed_{int(seed):02d}_{group}.jsonl') as write_decision:
                    for entries in classes.values():
                        for entry in entries:
                            for original in make_nidd_groups(entry['context'])[group]:
                                case = attach_reference(original, reference)
                                case['selection_seed'] = int(seed)
                                outcomes = evaluator.evaluate(case)
                                write_case(case)
                                write_decision({'case_id': case['case_id'], 'selection_seed': int(seed), 'expected_reference': case['expected_reference'], 'outcomes': outcomes})
                                metrics.add(case, outcomes)
                                overall.add(case, outcomes)
                                total += 1
                                group_counts[group] += 1
                                if total % 1000 == 0:
                                    run.checkpoint(proposals=total, selection_seed=int(seed))
            if group_counts != {'conformance': 4750, 'false_alarm_probes': 250}:
                raise ValueError('panel proposal denominators do not match design')
            per_seed[seed] = metrics.summary()
        run.write_json('summary.json', {'overall': overall.summary(), 'by_seed': per_seed,
                                       'paired_panel_occurrences_not_unique_records': True})
        run.checkpoint(proposals=total, comparator_decisions=total * 4)
        run.finish(True, conformance_proposals=95000, false_alarm_proposals=5000)
    except BaseException as exc:
        if not (output / 'RUN.json').exists():
            run.finish(False, error_type=type(exc).__name__)
        raise


CONDITIONS = {'original': {}, 'reduction60': {'maximum_reduction_percent': 60},
              'reduction90': {'maximum_reduction_percent': 90}, 'ttl300': {'maximum_ttl_seconds': 300},
              'ttl600': {'maximum_ttl_seconds': 600}, 'budget500': {'packet_budget': 500}, 'budget2000': {'packet_budget': 2000}}


def condition_settings(condition: str) -> tuple[ReferencePolicy, dict, int]:
    settings = dict(CONDITIONS[condition])
    budget = settings.pop('packet_budget', 1000)
    reference = ReferencePolicy().with_overrides(**settings)
    policy = strict_json_load(ROOT / 'configs/paper_policy.json', maximum_bytes=1024**2)
    if 'maximum_reduction_percent' in settings:
        policy['parameter_bounds']['rate_limit_ue']['reduction_percent']['maximum'] = settings['maximum_reduction_percent']
    if 'maximum_ttl_seconds' in settings:
        policy['max_ttl_seconds'] = settings['maximum_ttl_seconds']
    return reference, policy, budget


def iter_frozen_cases(paths: Iterable[Path]) -> Iterator[dict]:
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024**3:
            raise ValueError('case input must be regular nonsymlink JSONL <=1 GiB')
        with path.open('r', encoding='utf-8', newline='') as handle:
            while line := handle.readline(1024**2 + 1):
                if len(line.encode('utf-8')) > 1024**2:
                    raise ValueError('case JSONL line exceeds 1 MiB')
                case = strict_json_loads(line, maximum_bytes=1024**2)
                if not isinstance(case, dict) or not {'case_id', 'proposal', 'evaluation_time'} <= case.keys():
                    raise ValueError('invalid case envelope')
                yield case


def run_sensitivity(source: str, input_path: Path, condition: str, output: Path) -> None:
    if source == 'netslab' and condition.startswith('budget'):
        raise ValueError('packet-budget variation is 5G-NIDD-only')
    if source == 'nidd':
        panel_path = input_path / 'panels.json' if input_path.is_dir() else input_path
        verify_completed_input(panel_path.parent, ['panels.json'])
        inputs = {'panels': panel_path, 'census_receipt': panel_path.parent / 'RUN.json',
                  'census_supervisor_receipt': panel_path.parent.parent / 'COMPLETE.json'}
    else:
        directory = input_path if input_path.is_dir() else input_path.parent
        if not input_path.is_dir() and input_path.name != 'cases.jsonl':
            raise ValueError('NetsLab sensitivity requires the complete frozen cases.jsonl')
        inputs = verify_netslab_input(directory)
        paths = [inputs['cases']]
    run = EvaluationRun(output, f'stage3_{source}_{condition}', inputs)
    try:
        reference, policy, budget = condition_settings(condition)
        evaluator, metrics, per_seed, n = EvaluatorBundle(policy), Metrics(), {}, 0
        primary_reference = ReferencePolicy()
        if source == 'nidd':
            panels = load_panels(panel_path)
            def cases():
                for seed, classes in panels['seeds'].items():
                    for entries in classes.values():
                        for entry in entries:
                            for group in make_nidd_groups(entry['context'], budget).values():
                                for case in group:
                                    case['selection_seed'] = int(seed)
                                    yield case
            cases_iter = cases()
        else:
            cases_iter = iter_frozen_cases(paths)
        run.write_json('condition.json', {'condition': condition, 'source': source, 'policy': policy,
                                         'policy_sha256': canonical_digest(policy), 'reference_overrides': reference.overrides,
                                         'packet_budget_per_second': budget if source == 'nidd' else None,
                                         'proposal_change': 'budget-only' if condition.startswith('budget') else 'none; frozen original proposals'})
        counts = Counter()
        effects = Counter()
        adverse_conditions = Counter()
        category_metrics: dict[str, Metrics] = {}
        context_metrics: dict[str, Metrics] = {}
        seen_cases = set()
        with run.jsonl('decisions.jsonl') as write:
            for original in cases_iter:
                case = attach_reference(original, reference)
                seed = str(case.get('selection_seed', case.get('generation_seed', case.get('seed', 'unspecified'))))
                identity = (seed, case['case_id'])
                if identity in seen_cases:
                    raise ValueError('duplicate case within seed')
                seen_cases.add(identity)
                outcomes = evaluator.evaluate(case)
                metrics.add(case, outcomes)
                if seed not in per_seed:
                    per_seed[seed] = Metrics()
                per_seed[seed].add(case, outcomes)
                group = case.get('experiment_group', 'generated_controls')
                counts[group] += 1
                category = case.get('category', 'unspecified')
                category_metrics.setdefault(category, Metrics()).add(case, outcomes)
                context_kind = case.get('source_context', {}).get('kind', 'unspecified')
                context_metrics.setdefault(context_kind, Metrics()).add(case, outcomes)
                for rule in case['expected_reference']['violated_rules']:
                    adverse_conditions[rule] += 1
                baseline_case = original
                if condition.startswith('budget'):
                    baseline_case = next(c for c in make_nidd_groups(case['source_context']['observed'], 1000)[group]
                                         if c['category'] == category)
                baseline_reference = primary_reference.evaluate(baseline_case)
                effects['proposal_changed_from_primary'] += case['proposal'] != baseline_case['proposal']
                effects['expected_decision_changed_from_primary'] += case['expected_reference']['decision'] != baseline_reference['decision']
                effects['expected_reasons_changed_from_primary'] += set(case['expected_reference']['reasons']) != set(baseline_reference['reasons'])
                effects['cases'] += 1
                write({'case_id': case['case_id'], 'seed': seed, 'experiment_group': group,
                       'category': case.get('category'), 'proposal_sha256': canonical_digest(case['proposal']),
                       'proposal_parameters': case['proposal'].get('parameters') if isinstance(case['proposal'], dict) else None,
                       'primary_reference': baseline_reference,
                       'expected_reference': case['expected_reference'], 'outcomes': outcomes})
                n += 1
                if n % 1000 == 0:
                    run.checkpoint(proposals=n)
        if source == 'nidd' and counts != {'conformance': 95000, 'record_proposals': 20000, 'false_alarm_probes': 5000}:
            raise ValueError('NIDD sensitivity denominators mismatch')
        if source == 'netslab' and n != 20000:
            raise ValueError('NetsLab sensitivity must consume the complete 20,000-case frozen suite')
        run.write_json('summary.json', {'condition': condition, 'overall': metrics.summary(),
                                       'by_seed': {s: m.summary() for s, m in per_seed.items()},
                                       'by_category': {c: m.summary() for c, m in category_metrics.items()},
                                       'by_context_kind': {c: m.summary() for c, m in context_metrics.items()},
                                       'proposal_counts': counts, 'assumption_effect_on_fixed_inputs': dict(effects),
                                       'adverse_rule_counts_multiple_rules_may_apply': dict(adverse_conditions),
                                       'adverse_condition_note': 'False alarms remain a distinct group. Missing/unverifiable state, approval faults and stale proposals are reported in the retained categories/rule counts, not synthesized from absent telemetry.'})
        run.checkpoint(proposals=n, comparator_decisions=n * 4)
        run.finish(True, condition=condition, source=source)
    except BaseException as exc:
        if not (output / 'RUN.json').exists():
            run.finish(False, error_type=type(exc).__name__)
        raise
