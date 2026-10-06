# Research boundaries

## Completed internal scope

The delivered project completes the bounded scientific question it states: after one independently admitted complete event cut, determine and check the minimum sublist of original ranked candidates needed to preserve every allowed future answer under inherited expiry and monotone revocation. The result includes specification-level proofs, explicit tight constructions, a producer and separately coded checker, direct replay, exact small oracles, malformed-input and certificate-fault controls, bounded scaling cases, raw outcomes, a claim/evidence ledger, and clean-extraction reproduction.

The central exact laws are:

```
unrestricted: min(M, D * 2^u)
budget b:     min(M, D * sum_{k=0}^{min(b,u)} binom(u,k)).
```

Both are upper bounds with matching constructions for every admissible parameter choice, within the original-candidate sublist representation. Expiry alone and logarithmically many shared revocation tokens each yield independent no-compression regimes. The executable extremal constructors and tests check finite instances of these statements; the general validity rests on the written arguments.

## Fixed assumptions

The result is conditional on all of the following.

- The checker receives a complete admitted event prefix, immutable policy, and expected entity/attribute target independently of the producer and certificate.
- The current cut identifier and all later revocations are independently known.
- Evidence identifiers and candidate ranks are immutable and unique.
- Observation intervals and lifetimes are bounded integers, with no arithmetic wraparound.
- Derivations are conjunctive copy or finite-set union.
- All aliases in the admitted cut form an undirected forest.
- Revocation is monotone within the cut. The implemented certificate and verified cache cover unrestricted revocation. The budgeted laws and bounded exact helper are separate results; no budgeted certificate or cumulative-consumption guard is implemented.
- The answer includes candidate identity as well as value.
- The minimum is over sublists of original candidates, not arbitrary encodings.

Changing any of these can change the theorem, algorithm, or necessary representation.

## What the certificate does not establish

The artifact does not supply cryptographic log commitment, non-equivocation, signatures, authenticated clocks, source honesty, or proof that no external event was withheld before admission. It does not verify a physical service, Internet host identity, network coverage, vulnerability, or operational access policy. Passing the checker means that the certificate is semantically correct relative to the independently supplied cut and policy, not that those inputs describe the world correctly.

The bootstrap is intentionally not succinct. The checker needs the complete independent prefix and a classification of every relevant candidate. A one-entry warm cache is therefore not a one-entry proof of ingress completeness. Authenticated transparency or tamper-evident logging can protect the cut commitment, but those mechanisms do not by themselves prove future-answer completeness; conversely, this frontier does not authenticate the cut.

## Representation and generality limits

The exact-minimum theorem is for identity-preserving sublists of original candidates. It is not a lower bound on minimum bits, Boolean circuits, algebraic expressions, value-only caches, or graph-specific data structures. The explicit diamond example lower-bounds route lists only; circuits or dynamic connectivity structures may share alternative paths.

Forest aliases eliminate disjunctive route provenance. Cyclic or multi-route graphs require an OR-capable provenance representation. Unioning alternative route supports as an AND dependency would be unsound because one surviving route can preserve visibility.

The budgeted frontier is safe only when an independent mechanism enforces the cumulative budget from the origin cut. After consuming `k` of a total budget `b`, only `b-k` new revocations remain. Resetting the budget without rebootstrap can expose an omitted candidate.

Policy refinement is not free. Splitting a shared token into per-record tokens, changing lifetime semantics, adding observations, changing rank, or allowing revocation reinstatement can invalidate the old frontier. Such changes require a new admitted cut and certificate.

## Evidence limits

All inputs are generated bounded abstractions. Public schemas and literature motivate the fields, but the artifact contains no Censys export, live scan, real target address, exposed service, vulnerability label, private data, device measurement, or human study. The 997 case entries are semantic test instances, not representative Internet workloads. Counts establish exact agreement on included cases and exercise theorem consequences; they do not prove implementation correctness for all inputs.

Timing is descriptive of one execution environment. No claim is made about production throughput, distributed ingestion, persistent storage, network transport, authenticated revocation delivery, hardware acceleration, or workload prevalence. The private-scope negative case is retained because it shows that compression and speedup are not universal.

The Python implementation is not formally verified. Producer/checker module separation helps isolate implementation disagreements, but passing finite checks does not establish the general written arguments.

## Literature and novelty boundary

Event sourcing, provenance semirings, why/where provenance, antichain absorption, secure audit logs, transparency directories, authenticated freshness, provenance-aware storage, counterfactual causality, hitting-set reductions, and provenance circuits are prior foundations. The project does not claim to invent them.

The scoped contribution is the ranked temporal future-winner problem after a fixed admitted cut: inherited expiry, shared revocation authority, immutable identities, the unique minimum exact candidate sublist, the two matching cardinality laws, their no-compression thresholds, and a coverage certificate that checks every retained, covered, or initially inactive candidate against independent evidence. Secure-log and transparency mechanisms answer commitment; provenance and freshness mechanisms answer parts of eligibility; this work addresses answer completeness under future eligibility loss. These layers are complementary rather than substitutes.

The manuscript bibliography contains 24 cited scholarly references. The supplied historical calibration record describes 12 full papers from the target journal, five full adjacent-venue papers, and five foundational/influential papers; the last group deliberately overlaps the first two where a paper is both closest and field-defining. That record is not a new full-text audit of every citation in the current repair. Selected primary-source checks support proportional positioning, not an exhaustive literature review or guaranteed novelty against every unpublished result.

## External-use holds

Before submission or operational use, the following author and policy obligations remain:

1. Both named humans must review the full scientific content, approve authorship and contribution statements, and take responsibility for the work.
2. The live first-party TDSC author guide, current IEEE template selection, length/counting, supplement, link, anonymity, submission-frequency, authorship, originality, and AI-use rules must be rechecked at the time of submission.
3. Substantive AI assistance must be disclosed accurately; it must not be represented as grammar-only help or human-only research.
4. A real public artifact URL may be inserted only after upload and only where current venue rules permit it. No placeholder or invented URL is included.
5. Independent expert review, formal mechanization, production validation, peer acceptance, funding, and collaboration are not claimed.

The scoped results do not guarantee acceptance or authorize submission without those human and policy gates.
