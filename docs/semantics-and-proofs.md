# Semantics and proofs

This document states the mathematical contract implemented by the artifact. It is a specification-level proof record, not a machine-checked proof of the Python programs. Executable tests cover finite consequences and explicit extremal constructions; they do not replace the general arguments below.

## 1. Trust boundary and object of certification

A **cut** consists of an independently supplied complete admitted event prefix, an immutable policy, a cut identifier, and an integer lower bound `q0` on future query times. The policy fixes entities, attributes, source classes, authorization, source priorities, a finite revocation-token universe `U`, timestamp intervals, derivation rules, and alias permissions. The checker must obtain the complete prefix, the currently authorized cut identifier, and all later revocations through a route independent of the producer whose certificate it checks.

The artifact does not authenticate the physical clock, public keys, source statements, policy quality, Internet entities, or completeness of events that were never admitted. It is not a signature scheme, transparency service, or proof that a service still physically exists. Its claim begins only after one complete cut has been independently admitted. A new observation, policy revision, token split, revocation reinstatement, or new cut requires a new bootstrap.

Observation and derived records have immutable unique identifiers. Replaying an identical record is idempotent; reusing an identifier for different content is invalid. Parents are observation or derived nodes, and the parent graph is acyclic. The implemented derivation language contains copy and finite-set union with conjunctive provenance: every declared parent remains required even when the same value might have another explanation. Every record is checked against its own authorization; authorization is not silently inherited.

Alias attestations have authorized issuers, local lifetime bounds, optional evidence parents, and revocation scopes. All admitted alias edges, including initially inactive ones, must form an undirected forest. The implementation rejects an incompatible cyclic union rather than selecting an arrival-order-dependent spanning tree.

For one anchor and attribute, the semantic answer is the identifier and finite-set value of the live candidate with maximum immutable total rank, or absence. Rank is the declared tuple `(source priority, original lower timestamp, identifier)`. Identity is part of the answer. A system that treats equal values as interchangeable has a different minimization problem.

## 2. Robust freshness and conjunctive ancestry

An evidence item has an actual observation time `tau` in an admitted interval `[lo, hi]` and a positive lifetime `Delta`. All future queries satisfy `q >= q0 >= hi`. Robust half-open freshness requires

```
0 <= q - tau < Delta    for every tau in [lo, hi].
```

The lower inequality is automatic for future queries. The maximum possible age is attained at `tau = lo`, so robust freshness is exactly

```
q < lo + Delta.
```

The implementation accepts nonnegative integer timestamp endpoints and lifetimes at most `2^31 - 1`, requires positive lifetimes, rejects reversed intervals and future upper bounds, and permits deadlines at most `2^32 - 2`. Query times are at most `2^32 - 1`. Python integer addition is used; no wrapping arithmetic is assumed.

For a record or alias attestation `v`, let `C(v)` contain `v` and all transitive evidence parents. Define its compiled deadline and support by

```
d(v) = min { lo(u) + Delta(u) : u in C(v) }
S(v) = union { scope(u) : u in C(v) }.
```

A support is a set of revocation tokens, not a probability or multiplicity.

**Lemma 2 (ancestral liveness).** Under the admitted AND semantics, `v` is live at query time `q` after revoked set `R` exactly when `q < d(v)` and `S(v)` is disjoint from `R`.

**Proof.** Take a topological order of the parent DAG. A leaf satisfies its local deadline and scope predicates. A derived node conjoins its local predicate with every parent predicate already characterized by the induction hypothesis. Conjoining strict upper bounds takes their minimum, and requiring all support sets to avoid `R` takes their union. Repeated ancestors are idempotent under both operations. Therefore the recurrence is exact. In particular, copying or recomputing a value cannot reset an ancestor's expiry or remove an ancestor's revocation obligation. QED.

## 3. Forest aliases and unique-route compilation

For anchor `r` and a candidate whose base entity is `e`, a forest supplies either no route or one route `P(r,e)`. Include every alias attestation on that route and all of their evidence ancestors in the candidate closure. Equivalently, an alias summary `(d_j,S_j)` transfers a candidate summary by

```
T_j(rank,d,S) = (rank, min(d,d_j), S union S_j).
```

Base ownership and rank are unchanged.

**Lemma 3 (anchor equivalence).** In a forest cut, the transferred candidate is live exactly when its direct evidence is live and its base entity is connected to the anchor in the live alias forest.

**Proof.** A forest has at most one route between two vertices. The endpoints are connected in the live subgraph exactly when every attestation on that route is live. Apply Lemma 2 to the candidate and every route attestation, then conjoin their predicates. Minimum deadlines and unioned supports give the transferred summary. With no route, visibility is impossible; with `r=e`, the empty route adds no obligation. QED.

Initially disconnected candidates, candidates with `d <= q0`, and candidates whose supports intersect the already known revoked set are permanently inactive under a fixed cut and monotone revocation. Remove them before retention. Let `A` be the remaining finite candidate set; every `x in A` has distinct rank, deadline `d_x > q0`, and support `S_x subseteq U`.

## 4. Exact unrestricted future-winner frontier

For candidates `x,y in A`, define

```
y dominates x  iff
    rank_y > rank_x,
    d_y >= d_x, and
    S_y subseteq S_x.
```

Let `F(A)` contain exactly the undominated candidates. A query `(q,R)` is allowed when `q >= q0` and `R subseteq U`; revocation is monotone because only the cumulative set matters.

**Theorem 4 (winner preservation).** For every allowed query, the maximum live identity in `F(A)` equals the maximum live identity in `A`, including absence.

**Proof.** If `y` dominates `x` and `x` is live, then `q < d_x <= d_y`, and `R` avoiding `S_x` implies that it avoids `S_y`. Hence `y` is also live and outranks `x`; a dominated candidate cannot win. Strictly increasing ranks make every dominance chain finite, so each removed live candidate has a retained live dominator. Therefore the maximum is unchanged. QED.

**Theorem 5 (constructive necessity and unique minimum sublist).** Every `x in F(A)` is the unique winner at

```
q_x = d_x - 1,
R_x = U \ S_x.
```

Consequently `F(A)` is the unique inclusion-minimum and cardinality-minimum exact sublist of the original candidates.

**Proof.** Integer deadlines and `d_x > q0` give `q_x >= q0`, and `x` is live. Consider a higher-ranked `y`. If `d_y < d_x`, integer time gives `d_y <= q_x`, so `y` has expired. Otherwise `d_y >= d_x`; because `x` is undominated, `S_y` is not a subset of `S_x`, so `S_y` contains a token in `U \ S_x = R_x` and is revoked. Lower-ranked candidates cannot beat `x`. Thus every exact original-candidate sublist must retain `x`; Theorem 4 shows that retaining all and only frontier members suffices. QED.

This is a representation theorem. It does not minimize bits, circuits, value-only summaries, graph reachability structures, or encodings that can reconstruct candidates.

## 5. Exact unrestricted cardinality and no-compression thresholds

Let `M = |A|`, let `D` be the number of distinct candidate deadlines actually present, and let `u = |U|`. The empty instance has `M=D=0`; every nonempty instance necessarily satisfies `1 <= D <= M`.

**Theorem 6 (tight unrestricted size).**

```
|F(A)| <= min(M, D * 2^u),
```

and equality is attainable for every `u >= 0` and every legal `(M,D)`: either `M=D=0`, or `1 <= D <= M`.

**Proof of the upper bound.** There are only `D*2^u` distinct `(deadline,support)` summaries. With distinct ranks, two candidates sharing one summary are comparable and the higher-ranked one dominates the other. At most one frontier member occupies each summary. The candidate count `M` is the other cap. QED.

**Matching construction.** The empty case is immediate. Otherwise let `L=min(M,D*2^u)`. Select `L` distinct deadline/support pairs while covering every one of the `D` deadlines; this is possible because `D <= L <= D*2^u`. Rank one candidate per selected pair by `(-deadline, |support|, identifier)`. Whenever one summary lasts at least as long and uses a subset of another support, it receives a lower rank unless the summaries coincide, so all selected candidates are undominated. If `M>L`, add `M-L` lower-ranked copies of one selected summary; its selected original dominates every copy, no new winner appears, and the actual deadline count remains `D`. `tight_summary_grid` realizes the full grid and `tight_summary_instance` realizes every legal capped case.

**Corollary 7 (no-compression thresholds).** Two exact cases expose different no-compression mechanisms.

1. **Expiry alone.** With `u=0`, the exact worst case is `min(M,D)`. Rank earlier-expiring candidates higher; time successively exposes every candidate. The artifact's `expiry_ladder` supplies this witness.
2. **One deadline.** With `D=1`, the exact worst case is `min(M,2^u)`. Retaining all `M` candidates is possible if and only if `u >= ceil(log2 M)`. Distinct bit-mask supports, ranked so strict subsets have lower rank, attain the threshold. The artifact's `support_code` supplies this witness.

Private per-record scopes are therefore sufficient but not necessary for noncompression: only logarithmically many shared tokens can encode `M` indispensable winners. Conversely, no revocation token is needed when expiration times themselves supply `M` distinct contexts.

## 6. Composition and its explicit boundary

For compatible candidate sets using the same policy and rank semantics, let `L_(q,R)` filter to live candidates. Let a common alias transfer be `T(rank,d,S)=(rank,min(d,D0),S union C)`.

**Theorem 8 (composition).**

```
F(F(A) union F(B)) = F(A union B)
F(L_(q,R)(A))      = L_(q,R)(F(A))
F(T(F(A)))          = F(T(A)).
```

**Proof.** Dominance is transitive, so a candidate removed locally has a retained local dominator and remains removable after union; a globally undominated candidate could not have been locally dominated. A dominator cannot die while its dominated candidate survives because it has no earlier deadline and no additional support obligation. Common minimum preserves deadline order, common union preserves support inclusion, and rank is unchanged; a second frontier operation removes any new dominance introduced by transfer. QED.

Thus `A join B = F(A union B)` is associative, commutative, and idempotent on compatible canonical frontiers. It is not a total merge operator for arbitrary raw streams: conflicting identities, incompatible policies, and cyclic alias unions are rejected. Initially inactive transferred entries must be filtered before applying the minimum-retention interpretation.

The forest condition is substantive. A chain of `k` diamonds can have `2^k` source-to-anchor routes. Assigning distinct branch tokens can make every explicit route support necessary. This lower-bounds an explicit route list only. Boolean circuits can share repeated subgraphs, and general graph algorithms need not enumerate all paths. Cyclic or multi-route aliases require disjunctive provenance and a different checker representation; unioning all route supports as if they were conjunctive would be unsound.

## 7. Budgeted future revocation

Suppose policy independently guarantees that at most `b` additional distinct tokens may be revoked after the cut. For candidate `x`, let

```
H_x = { y : rank_y > rank_x and d_y >= d_x }
D_x = { S_y \ S_x : y in H_x }.
```

A family containing an empty set cannot be hit; the empty family needs no hits.

**Theorem 9 (budgeted possible-winner criterion).** Candidate `x` can win after at most `b` additional revocations if and only if `D_x` has a hitting set of size at most `b`. A witness can be chosen disjoint from `S_x` and used at time `d_x-1`.

**Proof.** If `x` wins, every higher-ranked candidate that remains unexpired at `d_x-1` must be disabled by a revoked token outside `S_x`; those tokens form a hitting set for `D_x`. Conversely, a hitting set outside `S_x` disables every member of `H_x` at `d_x-1`, while all higher-ranked candidates with earlier deadlines have expired. Then `x` is live and wins. QED.

Let `F_b(A)` contain exactly these possible winners. It is the minimum exact original-candidate sublist for all budget-feasible continuations, because every retained member has a witness and every feasible answer belongs to it. Pairwise nondominance is no longer sufficient: several higher-ranked candidates can require a collective set of revocations.

## 8. Exact budgeted cardinality

Define

```
N_b(u) = sum_{k=0}^{min(b,u)} binom(u,k).
```

**Theorem 10 (tight budgeted size).**

```
|F_b(A)| <= min(M, D * N_b(u)),
```

and equality is attainable for every `u,b >= 0` and every legal `(M,D)`: either `M=D=0`, or `1 <= D <= M`.

**Proof of the upper bound.** If `x` wins at any feasible `(q,R)`, moving time to `d_x-1` keeps `x` live and can only expire competitors. Hence every possible winner has a canonical witness `(d_x,R)` with `|R| <= b`. A fixed canonical context has only one highest-ranked live candidate. Possible winners therefore inject into the `D*N_b(u)` canonical contexts. QED.

**Matching construction.** The empty case is immediate. Otherwise let `L=min(M,D*N_b(u))`. Select `L` distinct canonical pairs `(d,R)` with `|R| <= b` while covering all `D` deadlines. Give the associated candidate support `U \ R` and rank `(-d, |U\R|, identifier)`. At context `(d-1,R)`, it is live; any other live selected candidate has deadline at least `d` and a revocation label containing `R`, and a strict relation lowers one of the first two rank components. Thus every selected candidate uniquely wins. If `M>L`, lower-ranked copies of one selected summary fill the candidate count without adding a winner or deadline. `tight_budget_grid` realizes the full grid and `tight_budget_instance` realizes every legal capped case.

Special cases are exact: `D` winners at `b=0`; `D(u+1)` at `b=1`; and `D*2^u` once `b>=u`, recovering Theorem 6. These are capacity laws after policy is fixed, not empirical prevalence estimates. Coalescing deadlines, coarsening token authority, or limiting the budget can reduce retained state only by changing the continuation semantics the system promises to answer.

## 9. Complexity and residual budgets

**Theorem 11 (variable-universe NP-completeness).** Deciding whether a designated candidate can win under a variable revocation budget is NP-complete even with one entity, one attribute, equal deadlines, and no aliases.

**Proof.** Membership follows by checking a proposed hitting set. For hardness, reduce Hitting Set. Given universe `V` and sets `E_1,...,E_m`, add a fresh token `z`. Create a lowest-ranked candidate `x` with support `{z}` and a higher-ranked candidate `y_i` with support `{z} union E_i`; give every candidate the same deadline. A winning context for `x` cannot revoke `z` and must choose within the budget at least one token from every `E_i`. Such a context exists exactly when the Hitting Set instance is feasible. Empty-set infeasibility is preserved, and the construction is polynomial. QED.

The artifact's `budget_witness` is deliberately an exact bounded enumerator over at most 20 relevant tokens. It is not presented as a polynomial algorithm for variable `u`.

If a cache was certified with total budget `b` and cumulative revoked set `R0` of size `k`, filtering that cache remains exact only for continuations adding at most `b-k` new tokens. Resetting the budget to `b` after consuming revocations can expose a candidate that the old cache was not required to keep. A budgeted certificate must bind its origin cut, total budget, and cumulative consumption.

## 10. Certificate soundness and completeness

A certificate repeats the cut, query lower bound, anchor, and attribute, but the trusted caller supplies the expected anchor and attribute independently. It also names every retained summary, one coverage witness for every omitted initially eligible candidate, and one reason for every initially inactive candidate. The checker rejects a repeated target that differs from the caller's expected target; the remaining classes form a complete disjoint partition for that target.

The checker reconstructs the cut rather than trusting supplied summaries. It validates schema closure, unknown fields, immutable replay, source permissions, derivation values, parent acyclicity, timestamps, token names, and the full forest condition. It reconstructs ancestry and the unique alias route; checks every retained identifier, rank, deadline, support, path, and value; checks retained mutual nondominance; verifies each omitted eligible candidate against a strict retained dominator; verifies inactive reasons; and rejects missing, duplicate, unknown, or extra classifications. Query guards bind the verified cache to its cut, caller-selected entity and attribute, permitted time domain, and token universe.

**Theorem 12 (certificate contract).** Assuming the independently supplied prefix, policy, and expected target are complete and valid, acceptance implies that the frozen cache is bound to that target and its answer equals direct replay for every allowed unrestricted continuation. Conversely, the producer can construct an accepted certificate for any well-formed caller-selected target from the compiled frontier and the complete candidate partition.

**Proof.** Input validation and Lemmas 2-3 make reconstructed candidate summaries exact. The expected-target check prevents same-cut entity or attribute substitution. Coverage then establishes that every omitted eligible candidate is dominated by a retained candidate; Theorem 4 preserves all future winners. Inactive candidates cannot become live under fixed-cut time advance and monotone revocation. Exact target/value/identity binding and query guards prevent redirection or stale-cut use. For completeness, compile the exact summaries, retain the frontier, give one valid dominator for every omitted eligible candidate, and classify every initially inactive candidate by its reconstructed reason; each checker condition then holds. QED.

The bootstrap is linear in the relevant admitted cut because the checker needs the complete independent prefix and a classification of every candidate. A small warm cache is not a succinct proof of unseen-ingress completeness. Authenticating only the retained entries would not prove that no necessary fallback was omitted.

## 11. Executable evidence and proof maturity

The producer and checker are separate modules; `freshcert/checker.py` imports neither the producer engine nor the frontier helper. The checker includes direct Boolean replay rather than calling the producer's dominance routine. This separation catches many implementation disagreements but is not independent authorship or formal verification.

The frozen campaign contains 768 abstract models and 229 generated event-stream cases, with 82,644 counted logical checks. A separate deterministic suite contains 31 interface and extremal tests. The extremal tests cover duplicate-summary elimination, the full `D*2^u` grid, 128 expiry-only indispensable candidates, logarithmic support codes, the exact budgeted construction over a small parameter grid, direct enumeration of every construction witness, a structured budget-one chain, and invalid parameters. General theorem maturity is therefore **proved at the specification level and finite-checked in code**, not machine-checked.

All inputs are generated bounded abstractions. No live scan, exposed service, vulnerability label, private data, external solver, GPU, remote model, or production deployment is used. Timing results are descriptive of one local execution and are not part of the universal mathematical claims.
