"""Focused API regressions using the included intake; no new stream campaign."""
import ast
from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import unittest
from freshcert.engine import Compiled
from freshcert.checker import AuditError, Prefix, check, verify
from freshcert.frontier import Candidate, frontier, query, budget_frontier

ROOT = Path(__file__).resolve().parents[1]


class Contract(unittest.TestCase):
    def setUp(self):
        self.raw = json.loads((ROOT/'inputs/intake.json').read_text())
        self.entity = 'e0'
        self.attr = self.raw['policy']['attributes'][0]
        self.cert = Compiled(self.raw).certificate(self.entity, self.attr)
        self.cache = verify(self.raw, self.cert, expected_entity=self.entity, expected_attribute=self.attr)

    def test_intake_certificate_is_exact_retained_control(self):
        expected = json.loads((ROOT/'results/reference/intake-certificate.json').read_text())
        self.assertEqual(self.cert, expected)

    def test_id_and_value_are_bound_to_prefix(self):
        p = Prefix(self.raw)
        got = self.cache.record(self.raw['q0'], (), current_cut=self.raw['cut'])
        key = p.direct(self.entity, self.attr, self.raw['q0'])
        self.assertEqual(got, (key, tuple(p.nodes[key]['value'])))

    def test_mutating_caller_prefix_cannot_mutate_verified_cache(self):
        expected = self.cache.record(self.raw['q0'], (), current_cut=self.raw['cut'])
        self.raw['events'].clear()
        self.cert['frontier'].clear()
        self.assertEqual(self.cache.record(self.raw['q0'], (), current_cut=self.raw['cut']), expected)

    def test_verified_cache_is_immutable(self):
        self.assertEqual((self.cache.entity, self.cache.attribute), (self.entity, self.attr))
        with self.assertRaises(FrozenInstanceError):
            self.cache.cut = 'other'
        with self.assertRaises(FrozenInstanceError):
            self.cache.entity = 'e2'
        with self.assertRaises(FrozenInstanceError):
            self.cache.attribute = 'other'

    def test_current_cut_is_required(self):
        with self.assertRaises(TypeError):
            self.cache.query(self.raw['q0'])

    def test_current_cut_is_checked(self):
        with self.assertRaises(AuditError):
            self.cache.query(self.raw['q0'], current_cut='other')

    def test_unknown_future_scope_is_rejected(self):
        with self.assertRaises(AuditError):
            self.cache.query(self.raw['q0'], ['not-a-policy-token'], current_cut=self.raw['cut'])

    def test_bool_is_not_query_time(self):
        with self.assertRaises(AuditError):
            self.cache.query(True, current_cut=self.raw['cut'])

    def test_query_time_does_not_wrap(self):
        self.assertIsNone(self.cache.query(2**32-1, current_cut=self.raw['cut']))

    def test_string_is_not_a_revocation_collection(self):
        with self.assertRaises(AuditError):
            self.cache.query(self.raw['q0'], 'a', current_cut=self.raw['cut'])

    def test_query_support_order_is_irrelevant(self):
        scopes = sorted(self.cache.tokens)
        self.assertEqual(self.cache.query(self.raw['q0'], scopes, current_cut=self.raw['cut']),
                         self.cache.query(self.raw['q0'], list(reversed(scopes)), current_cut=self.raw['cut']))

    def test_half_open_deadline(self):
        # Reuse the deadline/support of a retained original candidate.
        x = self.cache.entries[0]
        q = x.deadline
        p = Prefix(self.raw)
        self.assertEqual(self.cache.query(q, (), current_cut=self.raw['cut']),
                         p.direct(self.entity, self.attr, q))

    def test_certificate_unknown_fields_rejected(self):
        broken = deepcopy(self.cert)
        broken['unchecked'] = 1
        with self.assertRaises(AuditError):
            check(Prefix(self.raw), broken, expected_entity=self.entity, expected_attribute=self.attr)

    def test_expected_target_inputs_are_required(self):
        with self.assertRaises(TypeError):
            verify(self.raw, self.cert)
        with self.assertRaises(TypeError):
            check(Prefix(self.raw), self.cert)

    def test_same_cut_target_substitutions_are_rejected(self):
        prefix = Prefix(self.raw)
        entity_certificate = Compiled(self.raw).certificate('e2', 'tag')
        self.assertEqual(prefix.direct('e0', 'tag', 5, ()), 'copy')
        self.assertEqual(prefix.direct('e2', 'tag', 5, ()), 'outside')
        with self.assertRaisesRegex(AuditError, 'certificate.query_target'):
            check(prefix, entity_certificate,
                  expected_entity='e0', expected_attribute='tag')

        attribute_raw = deepcopy(self.raw)
        attribute_raw['policy']['attributes'].append('other')
        attribute_raw['policy']['sources']['a']['attributes'].append('other')
        attribute_raw['events'].append({
            'kind': 'observe', 'id': 'other', 'entity': 'e0',
            'attribute': 'other', 'value': [2], 'source': 'a',
            'lo': 0, 'hi': 0, 'ttl': 25, 'parents': [], 'rule': 'leaf',
        })
        attribute_prefix = Prefix(attribute_raw)
        attribute_certificate = Compiled(attribute_raw).certificate('e0', 'other')
        self.assertEqual(attribute_prefix.direct('e0', 'tag', 5, ()), 'copy')
        self.assertEqual(attribute_prefix.direct('e0', 'other', 5, ()), 'other')
        with self.assertRaisesRegex(AuditError, 'certificate.query_target'):
            check(attribute_prefix, attribute_certificate,
                  expected_entity='e0', expected_attribute='tag')

    def test_checker_has_no_producer_dependency(self):
        tree = ast.parse((ROOT/'freshcert/checker.py').read_text())
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(x.name for x in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or '')
        self.assertFalse(any('engine' in s or 'frontier' in s for s in imported))

    def test_empty_abstract_cache(self):
        self.assertEqual(frontier(()), ())
        self.assertIsNone(query((), 0, 0))

    def test_budget_domain_is_checked_for_empty_and_nonempty_inputs(self):
        item = Candidate('only', (0, 0, 'only'), 1, 0)
        for items in ((), (item,)):
            for budget in (-1, True, 1.5, '1', None):
                with self.subTest(items=len(items), budget=budget):
                    with self.assertRaises(ValueError):
                        budget_frontier(items, budget)
        self.assertEqual(budget_frontier((), 0), ())

    def test_budget_helper_on_included_three_candidate_world(self):
        # A selected, already frozen abstract case; compare exact possible winners.
        cases = [json.loads(x) for x in (ROOT/'inputs/abstract.jsonl').read_text().splitlines()]
        raw = cases[-1]
        a = tuple(Candidate(str(i), (0,0,str(i)), d, s)
                  for i, (d,s) in enumerate(zip(raw['deadlines'], raw['supports'])))
        possible = set()
        for q in range(4):
            for r in range(1 << raw['tokens']):
                if r.bit_count() <= 1:
                    eligible = [x for x in a if q < x.deadline and not (x.support & r)]
                    if eligible:
                        possible.add(max(eligible, key=lambda x:x.rank).identity)
        self.assertEqual({x.identity for x in budget_frontier(a, 1)}, possible)


if __name__ == '__main__':
    unittest.main()
