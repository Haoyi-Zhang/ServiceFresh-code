"""Tight constructions and size bounds for candidate frontiers.

These helpers expose policy-level worst cases used by the paper.  They do not
replace :mod:`freshcert.frontier`; every construction is checked by the same
frontier and budgeted-winner implementations as ordinary candidates.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from itertools import combinations, product
from math import comb

from .frontier import Candidate


def _positive_int(value: int, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def summary_pairs(candidates: Iterable[Candidate]) -> frozenset[tuple[int, int]]:
    """Return the distinct ``(deadline, support)`` summaries in *candidates*."""
    return frozenset((item.deadline, item.support) for item in candidates)


def summary_bound(candidates: Iterable[Candidate]) -> int:
    """Exact summary-diversity upper bound on unrestricted frontier size.

    At most one candidate with any fixed ``(deadline, support)`` pair can be
    undominated, because ranks are unique and the higher-ranked duplicate
    dominates every lower-ranked duplicate.
    """
    return len(summary_pairs(candidates))



def budget_context_bound(deadline_count: int, token_count: int, budget: int) -> int:
    """Return the context-count upper bound for budgeted possible winners.

    With ``deadline_count`` distinct deadlines, ``token_count`` revocation
    tokens, and at most ``budget`` revoked tokens, each possible winner has a
    canonical witness consisting of its deadline and one revocation set of size
    at most ``budget``.  A fixed canonical context has only one highest-ranked
    live candidate.  Hence the number of possible winners is at most::

        deadline_count * sum(comb(token_count, k), k=0..min(budget, token_count))

    The candidate count itself is an additional trivial cap applied by callers.
    """
    deadline_count = _positive_int(deadline_count, "deadline_count")
    if type(token_count) is not int or token_count < 0:
        raise ValueError("token_count must be a nonnegative integer")
    if type(budget) is not int or budget < 0:
        raise ValueError("budget must be a nonnegative integer")
    return deadline_count * sum(
        comb(token_count, size) for size in range(min(budget, token_count) + 1)
    )


def tight_budget_grid(
    deadlines: Sequence[int], token_count: int, budget: int
) -> tuple[Candidate, ...]:
    """Attain the budgeted context-count bound for every parameter choice.

    For every deadline ``d`` and revocation set ``R`` of size at most the
    budget, create a candidate whose support is the complement ``U minus R``.
    At time ``d - 1`` under revocations ``R``, that candidate is the unique
    highest-ranked live item.  The construction therefore realizes exactly::

        len(deadlines) * sum(comb(token_count, k), k=0..min(budget, token_count))

    possible winners.  The helper is deliberately bounded to 20 tokens,
    matching the exact budget-search oracle used by the artifact.
    """
    if not deadlines:
        raise ValueError("deadlines must be nonempty")
    if any(type(value) is not int or value <= 0 for value in deadlines):
        raise ValueError("deadlines must contain positive integers (live at q0=0)")
    if len(set(deadlines)) != len(deadlines):
        raise ValueError("deadlines must be distinct")
    if type(token_count) is not int or token_count < 0:
        raise ValueError("token_count must be a nonnegative integer")
    if type(budget) is not int or budget < 0:
        raise ValueError("budget must be a nonnegative integer")
    if token_count > 20:
        raise ValueError("token_count is limited to 20 for bounded fixtures")

    full_support = (1 << token_count) - 1
    items: list[Candidate] = []
    bits = tuple(1 << index for index in range(token_count))
    for deadline in sorted(deadlines):
        for size in range(min(budget, token_count) + 1):
            for chosen in combinations(bits, size):
                revoked = sum(chosen)
                support = full_support & ~revoked
                identity = f"budget-d{deadline}-r{revoked:06d}"
                rank = (-deadline, support.bit_count(), identity)
                items.append(Candidate(identity, rank, deadline, support))
    return tuple(items)


def _selected_deadline_labels(deadlines: Sequence[int], labels: Sequence[int], count: int):
    """Select ``min(count, capacity)`` pairs while preserving every deadline."""
    if type(count) is not int or count < 0:
        raise ValueError("count must be a nonnegative integer")
    if count == 0:
        if deadlines:
            raise ValueError("zero candidates require zero deadlines")
        return (), 0
    if not deadlines:
        raise ValueError("nonempty candidates require deadlines")
    if any(type(value) is not int or value <= 0 for value in deadlines):
        raise ValueError("deadlines must contain positive integers (live at q0=0)")
    if len(set(deadlines)) != len(deadlines):
        raise ValueError("deadlines must be distinct")
    if count < len(deadlines):
        raise ValueError("actual deadline count cannot exceed candidate count")
    pairs = [(deadline, labels[0]) for deadline in sorted(deadlines)]
    limit = min(count, len(deadlines) * len(labels))
    present = set(pairs)
    for pair in product(sorted(deadlines), labels):
        if len(pairs) == limit:
            break
        if pair not in present:
            pairs.append(pair)
            present.add(pair)
    return tuple(pairs), count - limit


def tight_summary_instance(
    candidate_count: int, deadlines: Sequence[int], token_count: int
) -> tuple[Candidate, ...]:
    """Attain ``min(M, D*2**u)`` with exactly ``M`` candidates and ``D`` deadlines.

    The nonempty legal domain is ``1 <= D <= M``.  Selected distinct summaries
    cover every supplied deadline.  When ``M`` exceeds summary capacity, lower-
    ranked copies of one selected summary fill the instance without adding a
    frontier member.  The empty legal instance has ``M = D = 0``.
    """
    if type(token_count) is not int or token_count < 0:
        raise ValueError("token_count must be a nonnegative integer")
    if token_count > 20:
        raise ValueError("token_count is limited to 20 for bounded fixtures")
    supports = tuple(range(1 << token_count))
    pairs, duplicate_count = _selected_deadline_labels(deadlines, supports, candidate_count)
    if not pairs:
        return ()
    items: list[Candidate] = []
    for index, (deadline, support) in enumerate(pairs):
        identity = f"summary-{index:06d}-d{deadline}-s{support:06d}"
        rank = (-deadline, support.bit_count(), identity)
        items.append(Candidate(identity, rank, deadline, support))
    base_rank = min(item.rank[0] for item in items) - 1
    template = items[0]
    for index in range(duplicate_count):
        identity = f"summary-copy-{index:06d}"
        items.append(Candidate(identity, (base_rank-index, -1, identity),
                               template.deadline, template.support))
    return tuple(items)


def tight_budget_instance(
    candidate_count: int, deadlines: Sequence[int], token_count: int, budget: int
) -> tuple[Candidate, ...]:
    """Attain ``min(M, D*N_b(u))`` with exactly ``M`` candidates and ``D`` deadlines."""
    if type(token_count) is not int or token_count < 0:
        raise ValueError("token_count must be a nonnegative integer")
    if type(budget) is not int or budget < 0:
        raise ValueError("budget must be a nonnegative integer")
    if token_count > 20:
        raise ValueError("token_count is limited to 20 for bounded fixtures")
    labels = tuple(mask for mask in range(1 << token_count)
                   if mask.bit_count() <= min(budget, token_count))
    pairs, duplicate_count = _selected_deadline_labels(deadlines, labels, candidate_count)
    if not pairs:
        return ()
    full_support = (1 << token_count) - 1
    items: list[Candidate] = []
    for index, (deadline, revoked) in enumerate(pairs):
        support = full_support & ~revoked
        identity = f"budget-{index:06d}-d{deadline}-r{revoked:06d}"
        rank = (-deadline, support.bit_count(), identity)
        items.append(Candidate(identity, rank, deadline, support))
    base_rank = min(item.rank[0] for item in items) - 1
    template = items[0]
    for index in range(duplicate_count):
        identity = f"budget-copy-{index:06d}"
        items.append(Candidate(identity, (base_rank-index, -1, identity),
                               template.deadline, template.support))
    return tuple(items)

def expiry_ladder(count: int, *, first_deadline: int = 1) -> tuple[Candidate, ...]:
    """Return a no-revocation construction whose entire list is a frontier.

    Higher-ranked candidates expire earlier.  Therefore no higher-ranked item
    lasts long enough to dominate a lower-ranked item, even though every support
    is empty.
    """
    count = _positive_int(count, "count")
    first_deadline = _positive_int(first_deadline, "first_deadline")
    items = []
    for index in range(count):
        deadline = first_deadline + index
        identity = f"expiry-{index:06d}"
        items.append(Candidate(identity, (-deadline, 0, identity), deadline, 0))
    return tuple(items)


def support_code(count: int, *, deadline: int = 1_000_000) -> tuple[Candidate, ...]:
    """Return an equal-deadline all-frontier construction using ceil(log2 n) tokens.

    Distinct bit masks encode the supports.  Ranks decrease along set inclusion:
    a strict subset has fewer bits and hence a lower rank, so it cannot dominate
    a strict superset.  Equal-cardinality distinct supports are incomparable.
    """
    count = _positive_int(count, "count")
    deadline = _positive_int(deadline, "deadline")
    # Exact ceil(log2(count)), including count=1, without floating rounding.
    token_count = (count - 1).bit_length()
    if count > (1 << token_count):  # defensive; mathematically unreachable
        raise AssertionError("insufficient support-code universe")
    items = []
    for support in range(count):
        identity = f"support-{support:06d}"
        items.append(
            Candidate(identity, (support.bit_count(), 0, identity), deadline, support)
        )
    return tuple(items)


def tight_summary_grid(
    deadlines: Sequence[int], token_count: int
) -> tuple[Candidate, ...]:
    """Realize every deadline/support pair and make all of them undominated.

    For distinct summaries, the summary order is acyclic.  The concrete rank
    ``(-deadline, |support|, identity)`` is a reverse linear extension: whenever
    one summary lasts at least as long and uses a subset of another's support,
    it receives a lower rank and therefore cannot dominate it.
    """
    if not deadlines:
        raise ValueError("deadlines must be nonempty")
    if any(type(value) is not int or value <= 0 for value in deadlines):
        raise ValueError("deadlines must contain positive integers (live at q0=0)")
    if len(set(deadlines)) != len(deadlines):
        raise ValueError("deadlines must be distinct")
    if type(token_count) is not int or token_count < 0:
        raise ValueError("token_count must be a nonnegative integer")
    if token_count > 20:
        raise ValueError("token_count is limited to 20 for bounded fixtures")

    items = []
    for deadline in sorted(deadlines):
        for support in range(1 << token_count):
            identity = f"grid-d{deadline}-s{support:06d}"
            rank = (-deadline, support.bit_count(), identity)
            items.append(Candidate(identity, rank, deadline, support))
    return tuple(items)


def budget_one_chain(count: int, *, deadline: int = 1_000_000) -> tuple[Candidate, ...]:
    """Return *count* candidates that are all possible winners with budget one.

    Candidates are ranked from ``chain-000001`` downward.  Candidate ``i`` has
    support ``{t_(i+1), ..., t_count}``; revoking ``t_i`` kills every candidate
    above it while preserving it.  The top candidate wins without revocation.
    The construction uses the ``count - 1`` tokens ``t_2, ..., t_count``;
    no separate ``t_1`` is introduced.  The top candidate's support contains
    all of these tokens even though it wins without revocation.
    """
    count = _positive_int(count, "count")
    deadline = _positive_int(deadline, "deadline")
    if count - 1 > 20:
        raise ValueError("count is limited to 21 by exact budget search")

    items = []
    for index in range(1, count + 1):
        support = 0
        for token_index in range(index + 1, count + 1):
            support |= 1 << (token_index - 2)  # t_2 is bit zero
        identity = f"chain-{index:06d}"
        # Smaller index is higher rank.
        rank = (count - index, 0, identity)
        items.append(Candidate(identity, rank, deadline, support))
    return tuple(items)
