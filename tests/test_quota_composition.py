"""Finite quota-composition controls using abstract findings, not scanner inputs."""
from dataclasses import replace
import random
import unittest

from promptguard.models import Finding, ScanResult
from promptguard.quota import explain_quota, quota_identity


class QuotaCompositionTests(unittest.TestCase):
    def cases(self):
        rng = random.Random(260114)
        pool = [Finding('FIXTURE_RULE', severity, path, 1, 'abstract finding',
                        'abstract excerpt')
                for severity, path in [('low', 'fixture/a.txt'),
                                       ('high', 'fixture/a.txt'),
                                       ('high', 'fixture/b.txt')]]
        for _ in range(12):
            rows = tuple(replace(rng.choice(pool), line=i + 1) for i in range(8))
            quotas = {quota_identity(f): rng.randrange(1, 5) for f in pool}
            yield rows, quotas

    def test_chunked_consumption_matches_one_pass(self):
        checks = 0
        for rows, quotas in self.cases():
            for threshold in ['info', 'high', 'critical']:
                for errors in [(), ('fixture:unreadable',)]:
                    policy = dict(min_severity=threshold, fail_on='high', max_findings=2)
                    whole = explain_quota(ScanResult(2, rows, errors), quotas, **policy)
                    saved = dict(quotas)
                    for cut in range(len(rows) + 1):
                        with self.subTest(check=checks, cut=cut):
                            left = explain_quota(ScanResult(1, rows[:cut]), quotas, **policy)
                            remaining = {e['identity']: e['remaining'] for e in left['entries']
                                         if e['remaining']}
                            right = explain_quota(ScanResult(1, rows[cut:], errors), remaining,
                                                  **policy)
                            combined = left['rows'] + [dict(r, index=r['index'] + cut,
                                                          declared_count=quotas.get(r['identity'], 0))
                                                       for r in right['rows']]
                            self.assertEqual(combined, whole['rows'])
                            right_remaining = {e['identity']: e['remaining']
                                               for e in right['entries']}
                            for entry in whole['entries']:
                                self.assertEqual(entry['remaining'],
                                                 right_remaining.get(entry['identity'], 0))
                            self.assertEqual(left['reported']['findings'] +
                                             right['reported']['findings'],
                                             whole['reported']['findings'])
                            count = sum(r['disposition'] == 'reported' for r in combined)
                            severity_failure = any(r['disposition'] == 'reported' and
                                                   r['finding']['severity'] == 'high'
                                                   for r in combined)
                            expected = 2 if errors else int(severity_failure or count > 2)
                            self.assertEqual(whole['gates']['exit_code'], expected)
                            self.assertEqual(quotas, saved)
                            checks += 1
        self.assertEqual(checks, 648)

    def test_more_allowance_cannot_add_reported_occurrences(self):
        checks = 0
        for rows, quotas in self.cases():
            for threshold in ['info', 'high', 'critical']:
                previous = None
                for allowance in range(5):
                    current = {identity: allowance for identity in quotas if allowance}
                    for errors in [(), ('fixture:unreadable',)]:
                        report = explain_quota(ScanResult(2, rows, errors), current,
                                               min_severity=threshold, fail_on='high',
                                               max_findings=2)
                        if errors:
                            self.assertEqual(report['gates']['exit_code'], 2)
                            continue
                        indices = set(report['reported_indices'])
                        if previous is not None:
                            self.assertLessEqual(indices, previous['indices'])
                            self.assertGreaterEqual(report['counts']['suppressed'],
                                                    previous['suppressed'])
                            self.assertLessEqual(report['gates']['exit_code'], previous['code'])
                            checks += 1
                        previous = dict(indices=indices, suppressed=report['counts']['suppressed'],
                                        code=report['gates']['exit_code'])
        self.assertEqual(checks, 144)
