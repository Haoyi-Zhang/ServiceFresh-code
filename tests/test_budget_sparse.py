"""Finite exact-search regressions for sparse nonnegative support masks."""
from itertools import combinations, product
import unittest

from freshcert.frontier import Candidate, budget_witness, query


def literal_witness(target, candidates, budget):
    edges = [item.support & ~target.support for item in candidates
             if item.rank > target.rank and item.deadline >= target.deadline]
    if any(edge == 0 for edge in edges):
        return None
    universe = 0
    for edge in edges:
        universe |= edge
    bits = [1 << index for index in range(universe.bit_length())
            if universe >> index & 1]
    for size in range(min(budget, len(bits)) + 1):
        for chosen in combinations(bits, size):
            witness = sum(chosen)
            if all(edge & witness for edge in edges):
                return witness
    return None


class SparseBudgetTests(unittest.TestCase):
    def setUp(self):
        self.target = Candidate('target', (0, 0, 'target'), 5, 0)

    def test_sparse_singletons_require_two_tokens(self):
        first, last = 1 << 3, 1 << 4095
        items = (self.target, Candidate('a', (1, 0, 'a'), 5, first),
                 Candidate('b', (2, 0, 'b'), 5, last))
        self.assertIsNone(budget_witness(self.target, items, 1))
        witness = budget_witness(self.target, items, 2)
        self.assertEqual(witness, first | last)
        self.assertEqual(query(items, 4, witness), self.target.identity)

    def test_canonical_order_matches_literal_dense_and_holey_masks(self):
        for a, b, c, budget in product(range(8), range(8), range(8), range(4)):
            items = (self.target,) + tuple(
                Candidate(str(i), (i + 1, 0, str(i)), 5, mask)
                for i, mask in enumerate((a, b, c)))
            self.assertEqual(budget_witness(self.target, items, budget),
                             literal_witness(self.target, items, budget))
        items = (self.target, Candidate('a', (1, 0, 'a'), 5,
                                       (1 << 3) | (1 << 4095)))
        self.assertEqual(budget_witness(self.target, items, 1), 1 << 3)

    def test_empty_and_unkillable_competitors(self):
        self.assertEqual(budget_witness(self.target, (), 0), 0)
        items = (Candidate('a', (1, 0, 'a'), 5, 0),)
        self.assertIsNone(budget_witness(self.target, items, 2))

    def test_bound_counts_relevant_tokens_not_largest_position(self):
        mask = sum(1 << (index * 257) for index in range(20))
        items = (Candidate('a', (1, 0, 'a'), 5, mask),)
        self.assertEqual(budget_witness(self.target, items, 1), 1)
        with self.assertRaisesRegex(ValueError, '20 tokens'):
            budget_witness(self.target,
                           (Candidate('a', (1, 0, 'a'), 5, mask | (1 << 6000)),), 1)

    def test_support_masks_have_the_documented_integer_domain(self):
        for mask in (-1, True, 1.5, None):
            with self.subTest(mask=mask):
                bad = Candidate('bad', (1, 0, 'bad'), 5, mask)
                with self.assertRaisesRegex(ValueError, 'support masks'):
                    budget_witness(bad, (), 1)
                with self.assertRaisesRegex(ValueError, 'support masks'):
                    budget_witness(self.target, (bad,), 1)


if __name__ == '__main__':
    unittest.main()
