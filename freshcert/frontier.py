"""Exact candidate frontiers. Original implementation; standard library only."""
from dataclasses import dataclass
from itertools import combinations
from typing import Iterable

@dataclass(frozen=True)
class Candidate:
    identity: str
    rank: tuple[int, int, str]
    deadline: int
    support: int
    path: tuple[str, ...] = ()

def dominates(y: Candidate, x: Candidate) -> bool:
    return y.rank > x.rank and y.deadline >= x.deadline and y.support & x.support == y.support

def frontier(candidates: Iterable[Candidate]) -> tuple[Candidate, ...]:
    """Input must have unique identities and ranks. Preserve exactly possible winners."""
    ordered = sorted(candidates, key=lambda x: x.rank, reverse=True)
    kept: list[Candidate] = []
    for x in ordered:
        if not any(y.deadline >= x.deadline and y.support & x.support == y.support for y in kept):
            kept.append(x)
    return tuple(kept)

def query(candidates: Iterable[Candidate], clock: int, revoked: int = 0) -> str | None:
    best = None
    for x in candidates:
        if clock < x.deadline and not x.support & revoked and (best is None or x.rank > best.rank):
            best = x
    return None if best is None else best.identity

def transfer(candidates: Iterable[Candidate], deadline: int, support: int) -> tuple[Candidate, ...]:
    return tuple(Candidate(x.identity, x.rank, min(x.deadline, deadline), x.support | support, x.path)
                 for x in candidates)

def budget_witness(x: Candidate, candidates: Iterable[Candidate], budget: int) -> int | None:
    """Exact finite hitting-set search; the caller must bound the token universe.

    Return a killing set of <=budget tokens for higher, no-shorter-lived candidates.
    None means x cannot win. This is not a polynomial-time general-budget algorithm.
    """
    if type(budget) is not int or budget < 0:
        raise ValueError('budget must be a nonnegative integer')
    edges = [y.support & ~x.support for y in candidates
             if y.rank > x.rank and y.deadline >= x.deadline]
    if any(edge == 0 for edge in edges):
        return None
    if not edges:
        return 0
    universe = 0
    for edge in edges:
        universe |= edge
    if universe.bit_count() > 20:
        raise ValueError('bounded exact search is limited to 20 tokens')
    bits = [1 << i for i in range(universe.bit_length()) if universe >> i & 1]
    for size in range(min(budget, len(bits)) + 1):
        for chosen in combinations(bits, size):
            hit = sum(chosen)
            if all(edge & hit for edge in edges):
                return hit
    return None

def budget_frontier(candidates: Iterable[Candidate], budget: int) -> tuple[Candidate, ...]:
    items = tuple(candidates)
    return tuple(x for x in items if budget_witness(x, items, budget) is not None)
