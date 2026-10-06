import math
import unittest

from freshcert.extremal import (
    budget_context_bound,
    budget_one_chain,
    expiry_ladder,
    summary_bound,
    summary_pairs,
    support_code,
    tight_budget_grid,
    tight_budget_instance,
    tight_summary_grid,
    tight_summary_instance,
)
from freshcert.frontier import Candidate, budget_frontier, budget_witness, frontier, query


class SummaryDiversityTests(unittest.TestCase):
    def test_duplicate_summary_contributes_at_most_one(self) -> None:
        items = (
            Candidate("high", (2, 0, "high"), 10, 3),
            Candidate("low", (1, 0, "low"), 10, 3),
            Candidate("other", (0, 0, "other"), 11, 1),
        )
        self.assertEqual(summary_bound(items), 2)
        self.assertLessEqual(len(frontier(items)), summary_bound(items))
        self.assertNotIn("low", {item.identity for item in frontier(items)})

    def test_tight_grid_realizes_every_summary(self) -> None:
        items = tight_summary_grid((7, 11, 19), 3)
        self.assertEqual(len(items), 3 * 2**3)
        self.assertEqual(len(summary_pairs(items)), len(items))
        self.assertEqual(len(frontier(items)), len(items))
        for count in (3, 4, 7, 24, 27):
            partial = tight_summary_instance(count, (7, 11, 19), 3)
            self.assertEqual(len(partial), count)
            self.assertEqual({item.deadline for item in partial}, {7, 11, 19})
            self.assertEqual(len(frontier(partial)), min(count, 3 * 2**3))
        self.assertEqual(tight_summary_instance(0, (), 3), ())

    def test_expiry_alone_can_prevent_compression(self) -> None:
        items = expiry_ladder(128, first_deadline=100)
        self.assertTrue(all(item.support == 0 for item in items))
        self.assertEqual(len(frontier(items)), 128)

    def test_every_tight_summary_candidate_has_direct_winner_witness(self) -> None:
        token_count = 3
        universe = (1 << token_count) - 1
        items = tight_summary_grid((7, 11, 19), token_count)
        for item in items:
            revoked = universe & ~item.support
            self.assertEqual(query(items, item.deadline - 1, revoked), item.identity)

    def test_logarithmic_support_code_can_prevent_compression(self) -> None:
        for count in (1, 2, 3, 7, 8, 31, 64, 127):
            items = support_code(count)
            universe = 0
            for item in items:
                universe |= item.support
            expected = 0 if count == 1 else math.ceil(math.log2(count))
            self.assertLessEqual(universe.bit_count(), expected)
            self.assertEqual(len(summary_pairs(items)), count)
            self.assertEqual(len(frontier(items)), count)

    def test_constructors_validate_inputs(self) -> None:
        for bad in (0, -1, 1.5, True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    expiry_ladder(bad)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            tight_summary_grid((), 1)
        with self.assertRaises(ValueError):
            tight_summary_grid((1, 1), 1)
        with self.assertRaises(ValueError):
            tight_summary_grid((1,), -1)
        with self.assertRaises(ValueError):
            tight_budget_grid((), 1, 1)
        with self.assertRaises(ValueError):
            tight_budget_grid((1, 1), 1, 1)
        with self.assertRaises(ValueError):
            tight_budget_grid((1,), -1, 1)
        with self.assertRaises(ValueError):
            tight_budget_grid((1,), 1, -1)
        with self.assertRaises(ValueError):
            tight_summary_instance(1, (1, 2), 0)
        with self.assertRaises(ValueError):
            tight_summary_instance(0, (1,), 0)
        with self.assertRaises(ValueError):
            tight_budget_instance(1, (1, 2), 0, 0)
        with self.assertRaises(ValueError):
            tight_budget_instance(0, (1,), 0, 0)

    def test_constructor_deadlines_are_live_at_natural_origin(self) -> None:
        for bad in (0, -1, True, 1.5):
            constructors = (
                lambda: expiry_ladder(2, first_deadline=bad),
                lambda: support_code(2, deadline=bad),
                lambda: budget_one_chain(2, deadline=bad),
                lambda: tight_summary_grid((bad, 3), 1),
                lambda: tight_budget_grid((bad, 3), 1, 1),
                lambda: tight_summary_instance(2, (bad, 3), 1),
                lambda: tight_budget_instance(2, (bad, 3), 1, 1),
            )
            for index, construct in enumerate(constructors):
                with self.subTest(deadline=bad, constructor=index):
                    with self.assertRaises(ValueError):
                        construct()

    def test_smallest_positive_deadline_has_admissible_witnesses(self) -> None:
        families = (
            expiry_ladder(2, first_deadline=1),
            support_code(2, deadline=1),
            budget_one_chain(2, deadline=1),
            tight_summary_grid((1, 3), 1),
            tight_budget_grid((1, 3), 1, 1),
            tight_summary_instance(2, (1, 3), 1),
            tight_budget_instance(2, (1, 3), 1, 1),
        )
        for items in families:
            universe = 0
            for item in items:
                universe |= item.support
            for item in items:
                self.assertGreaterEqual(item.deadline - 1, 0)
                self.assertEqual(query(items, item.deadline - 1,
                                       universe & ~item.support), item.identity)


class BudgetContextBoundTests(unittest.TestCase):
    def test_closed_form_values(self) -> None:
        self.assertEqual(budget_context_bound(3, 0, 9), 3)
        self.assertEqual(budget_context_bound(2, 4, 0), 2)
        self.assertEqual(budget_context_bound(1, 7, 1), 8)
        self.assertEqual(budget_context_bound(5, 3, 3), 5 * 2**3)
        self.assertEqual(budget_context_bound(5, 3, 99), 5 * 2**3)

    def test_budget_one_chain_meets_bound(self) -> None:
        for count in (1, 2, 3, 8, 16, 21):
            items = budget_one_chain(count)
            token_count = max(0, count - 1)
            self.assertEqual(
                len(budget_frontier(items, 1)),
                min(count, budget_context_bound(1, token_count, 1)),
            )

    def test_tight_grid_attains_bound_for_all_small_parameters(self) -> None:
        for deadline_count in (1, 2, 3):
            deadlines = tuple(10 + 7 * i for i in range(deadline_count))
            for token_count in range(5):
                for budget in range(token_count + 2):
                    with self.subTest(
                        deadlines=deadline_count, tokens=token_count, budget=budget
                    ):
                        items = tight_budget_grid(deadlines, token_count, budget)
                        self.assertEqual(
                            len(items),
                            budget_context_bound(deadline_count, token_count, budget),
                        )
                        self.assertEqual(len(budget_frontier(items, budget)), len(items))
                        capacity = budget_context_bound(deadline_count, token_count, budget)
                        for count in (deadline_count, capacity, capacity + 2):
                            exact = tight_budget_instance(count, deadlines, token_count, budget)
                            self.assertEqual(len(exact), count)
                            self.assertEqual({item.deadline for item in exact}, set(deadlines))
                            self.assertEqual(len(budget_frontier(exact, budget)),
                                             min(count, capacity))

    def test_tight_budget_grid_wins_under_direct_context_enumeration(self) -> None:
        for deadline_count in (1, 2):
            deadlines = tuple(20 + 5 * i for i in range(deadline_count))
            for token_count in range(4):
                universe = range(1 << token_count)
                for budget in range(token_count + 1):
                    with self.subTest(
                        deadlines=deadline_count, tokens=token_count, budget=budget
                    ):
                        items = tight_budget_grid(deadlines, token_count, budget)
                        winners = {
                            query(items, deadline - 1, revoked)
                            for deadline in deadlines
                            for revoked in universe
                            if revoked.bit_count() <= budget
                        }
                        winners.discard(None)
                        self.assertEqual(winners, {item.identity for item in items})

    def test_rejects_bad_parameters(self) -> None:
        for args in ((0, 1, 1), (1, -1, 1), (1, 1, -1), (True, 1, 1)):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    budget_context_bound(*args)


class BudgetOneTests(unittest.TestCase):
    def test_every_chain_candidate_has_a_one_token_witness(self) -> None:
        items = budget_one_chain(16)
        kept = budget_frontier(items, 1)
        self.assertEqual(tuple(item.identity for item in kept), tuple(item.identity for item in items))
        for position, item in enumerate(items):
            witness = budget_witness(item, items, 1)
            self.assertIsNotNone(witness)
            assert witness is not None
            self.assertLessEqual(witness.bit_count(), 1)
            self.assertEqual(query(items, 0, witness), item.identity)
            if position == 0:
                self.assertEqual(witness, 0)
            else:
                self.assertEqual(witness, 1 << (position - 1))

    def test_full_budget_recovers_unrestricted_possible_winners(self) -> None:
        items = budget_one_chain(8)
        self.assertEqual(
            tuple(item.identity for item in budget_frontier(items, 7)),
            tuple(item.identity for item in frontier(items)),
        )


if __name__ == "__main__":
    unittest.main()
