# Freshness and provenance certificates

A bounded offline reference implementation for **Revocation-Aware Frontiers and Tight Retention Bounds for Fresh Service-Map Records**. The repository contains an event-stream compiler, a separately implemented checker, direct Boolean replay, exact small-model oracles, explicit tight constructions, generated inputs, negative controls, retained raw results, and a claim/evidence ledger. It uses only the Python standard library and needs no network, solver, GPU, external model, private data, or live service.

## Result in one page

After one independently admitted complete event cut, fix authorization, source priorities, revocation-token meanings, conjunctive derivations, forest aliases, immutable candidate ranks, and monotone revocation. Each candidate compiles to an inherited deadline `d` and revocation support `S`.

For unrestricted future time advance and revocation, the exact retained set is the rank/deadline/support frontier: remove `x` when a higher-ranked `y` has `d_y >= d_x` and `S_y subseteq S_x`. This frontier preserves the winning **identity and value** for every allowed continuation and is the unique minimum sublist of the original candidates with that property.

If there are `M` candidates, `D` distinct deadlines, and `u` revocation tokens, the exact worst-case frontier size is

```
min(M, D * 2^u).
```

The bound is attained. Expiry alone can require `min(M,D)` candidates, and with one deadline only `ceil(log2 M)` tokens are sufficient to make all `M` candidates indispensable.

If policy independently limits the continuation to at most `b` additional token revocations, a candidate is possible exactly when a size-`b` hitting set disables every higher-ranked competitor that survives to its last live time. The exact worst-case number of possible winners is

```
min(M, D * sum(binom(u,k), k=0..min(b,u))).
```

This bound is also attained. Variable-universe membership is NP-complete; the implementation's exact helper is intentionally bounded to 20 relevant tokens.

These are minimum **original-candidate sublist** results, not minimum-bit or minimum-circuit results. They do not promise compression. At 2,000 private-scope candidates, every candidate remains necessary and certificate bootstrap costs more than building the matched full cache.

Complete arguments and boundaries are in `docs/semantics-and-proofs.md` and `docs/research-boundaries.md`.

## Trust boundary

The checker must receive the complete admitted prefix, policy, current cut identifier, expected entity, expected attribute, and subsequent revocations through an independently trusted route. The certificate repeats the target but cannot select it: `check`/`verify` require the caller's expected target, compare it before reconstruction, and store it in the frozen `Verified` cache. Giving the checker only producer-selected history or a producer-selected target would make a self-authenticated or redirectable certificate. The artifact does not authenticate signatures, public keys, physical clocks, source truth, real Internet identity, or unseen ingress. New observations, policy changes, token refinement, revocation reinstatement, or a new cut require rebootstrap.

The admitted derivation language is AND-only copy and finite-set union; aliases form a forest. The answer includes evidence identity. Multiple alternative alias routes, value-only equivalence, cyclic graphs, correlated revocation constraints, and richer derivation languages can change the representation and minimum-retention problem.

## Reproduce

Use Linux with Python 3.10 or later. Resource guards rely on Linux affinity and Unix `resource`; this is intentionally not a portable Windows benchmark. From the repository root:

```sh
python -m unittest discover -s tests -v
python reproduce.py --all --out results/reproduced --compare results/reference
python report.py --results results/reference --out results/paper-data
```

The deterministic regression suite has **31 tests**: 18 interface/contract tests and 13 extremal tests. The frozen campaign invokes one sequential child at a time and has **82,644 logical checks across 997 case entries**: 768 abstract models and 229 generated event-stream cases, not 997 Internet workloads. The largest generated case has 2,000 provenance records.

Each scientific phase has a 100-second CPU limit, 120-second wall limit, and 2,500,000,000-byte address-space limit. A complete run refuses more than 85,000 counted obligations. `--compare` requires exact equality of 23 discrete result files and all non-timing fields of 18 case tables; timing values are deliberately not compared bit-for-bit. A mismatch raises an exception and returns nonzero.

A bounded phase can be resumed into an existing incomplete output directory:

```sh
python reproduce.py --phase traces --index 3 --out results/reproduced
python reproduce.py --phase scale --index 11 --out results/reproduced
python reproduce.py --phase summary --out results/reproduced --compare results/reference
```

Other phases are `inputs`, `tiny`, and `faults`. Trace indices are 0-5 and scaling indices are 0-11. A summary requires all 21 phase results. For a genuinely independent rerun, use a fresh output directory rather than combining measurements from different campaigns.

## Minimal API example

```python
import json
from pathlib import Path

from freshcert.checker import verify
from freshcert.engine import Compiled

raw = json.loads(Path("inputs/intake.json").read_text())
certificate = Compiled(raw).certificate("e0", "tag")
cache = verify(raw, certificate,  # raw and target must be independently selected
               expected_entity="e0", expected_attribute="tag")
print(cache.record(raw["q0"], (), current_cut=raw["cut"]))
```

The producer import demonstrates the local toy pipeline; a deployed verifier would not obtain its trusted prefix or expected target from that producer. Both expected-target keywords are mandatory at bootstrap, and the frozen cache exposes `cache.entity` and `cache.attribute`. `current_cut` is mandatory at query time. `AuditError` reports malformed input, target/certificate mismatch, or a query-guard violation. `InvalidStream` is the producer-side validation exception.

## Repository map

- `freshcert/engine.py`: event validation, topological compilation, integer support bitsets, and certificate production.
- `freshcert/checker.py`: separately coded validation, ancestry/route reconstruction, coverage checking, verified cache, and direct Boolean replay. It imports neither `engine` nor `frontier`.
- `freshcert/frontier.py`: dominance, unrestricted frontier, query semantics, common transfer, and bounded exact budget witnesses.
- `freshcert/extremal.py`: exact cardinality formulas and matching constructions for unrestricted and budgeted retention.
- `freshcert/cases.py`: frozen deterministic generators.
- `tests/`: interface, immutability, boundary, and extremal-regression tests.
- `inputs/`: exact lawful generated inputs and invalid/valid controls.
- `results/reference/`: retained campaign outcomes.
- `results/clean/`: clean reproduction evidence for the delivered source.
- `results/paper-data/`: CSV and TeX derived from raw reference outcomes.
- `claim_evidence_ledger.csv`: each material claim mapped to proof, code, test, raw result, maturity, and boundary.
- `external_resources.csv`: scholarly, policy, template, and software sources with acquisition and integration notes.
- `docs/`: input, measurement, run-environment, resource, mathematical, and research-boundary contracts.

The repository is standalone. It does not require the paper directory, a private path, an omitted cache, a remote controller, or a third-party implementation.

## Evidence summary

The producer/checker cache agrees with direct replay in all 4,608 frozen query contexts. The timestamp-only baseline returns an ineligible record in 1,751 contexts. Retaining only the current top candidate causes 1,534 identity/completeness errors while not returning an ineligible record. Eighteen invalid streams are rejected independently by producer and checker; six valid controls are accepted; twenty effective certificate mutations and four invalid cache queries are rejected.

The scaling cases include shared scopes, independent private scopes, and conjunctive chains at 256, 512, 1,024, and 2,000 records. They isolate semantic regimes rather than estimate Internet workload prevalence. Shared scopes retain one candidate; private scopes retain all candidates; chains retain four. The matched full-cache baseline uses the same set representation and query routine as the frontier cache. Build/check/full-setup values are single observations per case; only warm-query values are medians of five batch means. The reference run did not retain exact Python, CPU/architecture, OS/image, or actual affinity identifiers, so its absolute timings are descriptive and cannot be exactly recreated from the package. `docs/run-environments.md` distinguishes those unrecorded fields from the fully recorded post-repair clean execution.

## Rights and status

Original code, generated inputs, and original documentation are provided under the MIT license in `LICENSE`. No third-party paper PDF or scientific implementation is redistributed. The paper package separately retains the upstream publisher typography license.

The scoped mathematics, implementation, finite validation, generated campaign, claim ledger, and clean reproduction are complete as internal research. The work has not undergone independent peer review, formal mechanization, Internet deployment, or acceptance review. Substantive AI assistance covered formulation, proofs, code, execution, analysis, literature inspection, writing, and self-audit; it was not language editing only. Human authors must approve authorship, verify live venue rules and template requirements, make all required AI-use and ethics disclosures, and supply a real repository URL before any external use.
