# Fresh service-map retention certificates

Bounded offline reference implementation for *Revocation-Aware Frontiers and Tight Retention Bounds for Fresh Service-Map Records*. It contains an event-stream compiler, separately implemented certificate checker, direct Boolean replay, exact small-model oracles, extremal constructions, generated inputs, and retained raw results.

The unrestricted certificate retains the rank/deadline/revocation-support frontier while preserving future winning identity and value under the declared continuations. The budgeted helper is a bounded exact search, not a budget-bound certificate or cumulative-budget enforcement mechanism. Complete arguments, cardinality laws, and representation limits are in [docs/semantics-and-proofs.md](docs/semantics-and-proofs.md) and [docs/research-boundaries.md](docs/research-boundaries.md).

## Environment and inputs

Use Python 3.10+ and the standard library only; no package installation, network, solver, GPU, external model, private data, or live service is required. Library tests and the API below are portable. Full reproduction uses **Linux** affinity and Unix `resource` controls; native Windows is not a supported benchmark/reproduction path. CI uses Python 3.12 on Ubuntu 24.04.

Run from this directory, or the root of either flat public repository. All scientific inputs are included in `inputs/`: 768 abstract models and 229 generated event-stream cases (997 entries), with at most 2,000 provenance records per included case. They are synthetic schema-inspired inputs, not Internet workloads. [docs/input-contract.md](docs/input-contract.md) defines the exact schemas and inventory.

## Tests and minimal API

```sh
python -B -m unittest discover -s tests -v
```

Current discovery contains **47** methods, including sparse-support budget checks, integer token-sizing boundaries, interface/extremal checks, ancestry-reuse regressions, and exact report-data regeneration. The retained 31-test clean log and later 40-test snapshot are historical, not the current discovery count. These tests remain separate from the frozen 82,644 campaign obligations.

```python
import json
from pathlib import Path
from freshcert.checker import verify
from freshcert.engine import Compiled

raw = json.loads(Path("inputs/intake.json").read_text())
certificate = Compiled(raw).certificate("e0", "tag")
cache = verify(raw, certificate,
               expected_entity="e0", expected_attribute="tag")
print(cache.record(raw["q0"], (), current_cut=raw["cut"]))
```

The producer import demonstrates the local toy pipeline. In an integration, the complete admitted prefix, policy, target, cut, and subsequent revocations must reach the checker independently of the producer. Expected-target keywords are mandatory at bootstrap; `current_cut` is mandatory on queries. `AuditError` reports malformed input, certificate/target mismatch, or query-guard violations; `InvalidStream` is the producer-side validation exception.

## Full reproduction and result derivation

Use a disposable copy of the repository on Linux and fresh scratch destinations:

```sh
python -B reproduce.py --all --out results/local-run --compare results/reference
python -B report.py --results results/reference --out results/local-paper-data
```

The `inputs` phase regenerates included input files in the working copy; phase and report outputs can overwrite existing files. Never direct outputs to `results/reference/`, `results/clean/`, or the supplied `results/paper-data/`. The two example destinations above are scratch paths.

The runner executes 21 scientific phases sequentially. Each phase has 100 CPU seconds, 120 wall seconds, 2,500,000,000 bytes of address space, and one-core affinity. The whole campaign refuses more than 85,000 counted obligations. A successful comparison requires exact equality of 23 discrete result files and all non-timing fields of 18 case tables; timing equality is excluded and mismatches return nonzero.

An incomplete run can resume individual phases:

```sh
python -B reproduce.py --phase traces --index 3 --out results/local-run
python -B reproduce.py --phase scale --index 11 --out results/local-run
python -B reproduce.py --phase summary --out results/local-run --compare results/reference
```

Other phases are `inputs`, `tiny`, and `faults`; trace indices are 0–5 and scale indices 0–11. Summary requires all 21 phase records. Use a fresh working copy and destination for a new campaign rather than combining measurements from different executions.

`report.py` reads retained reference outcomes and validates aggregate error counts and raw timing medians before writing nine CSV/TeX table/plot-data files. CI runs source integrity, ancestry and whole-suite tests, Linux reproduction/comparison, then report regeneration and exact comparison with `results/paper-data/`. Raw logs are uploaded even after a failed gate. Report generation is not a new timing experiment.

## Materials and retained evidence

- `freshcert/engine.py`, `checker.py`: producer validation/compilation and separate target-bound checker/cache. Checker ancestry reductions are call-local; it imports neither engine nor frontier.
- `freshcert/frontier.py`, `extremal.py`: frontier/query semantics, bounded budget witnesses, exact cardinality formulas and constructions.
- `freshcert/cases.py`, `inputs/`: deterministic generators and exact included inputs.
- `tests/`: executable contract, boundary, construction, sparse-support, and ancestry checks.
- `results/reference/`, `results/clean/`: retained campaign outputs and historical clean-reproduction evidence.
- `results/paper-data/`: derived data consumed by the paper's tables/plot.
- `claim_evidence_ledger.csv`, `external_resources.csv`: claim-to-proof/check/result links and external-source identities, access, rights, and integration notes.
- `docs/`: proof, input, measurement, environment, resource-accounting, and research-boundary contracts.

The retained cache agrees with direct replay in 4,608 generated query contexts. Shared, private, and chain scaling regimes distinguish retention behavior, not deployment prevalence. Private scopes can require retaining every candidate and cost more to bootstrap than a matched full cache; no universal compression or measured speedup from ancestry reuse is claimed.

Reference timings predate current ancestry reuse and lack exact Python/CPU/OS/affinity identifiers. They remain descriptive retained observations; later metadata is not substituted. Build/check/full-setup columns have one observation per case, while warm-query columns summarize five batch means. See [docs/measurement-contract.md](docs/measurement-contract.md), [docs/run-environments.md](docs/run-environments.md), and [docs/resource-accounting.md](docs/resource-accounting.md).

## Conditions and licensing

The model fixes a complete admitted cut, authorization, priorities, token meanings, immutable ranks, AND-only copy/finite-set union derivations, forest aliases, and monotone revocation. New observations, policy changes, token refinement, reinstatement, or a new cut require rebootstrap. Multiple alias routes, value-only equivalence, correlated constraints, and richer derivation languages change the problem.

The artifact does not authenticate signatures, clocks, keys, source truth, Internet identities, or unseen ingress. The results minimize an original-candidate sublist, not bits or circuits. Exact budget search is limited to 20 relevant tokens. Finite tests and written proofs do not supply formal code verification, independent peer review, deployment performance, or venue acceptance.

Original code, generated inputs, and documentation are MIT-licensed under `LICENSE`. No third-party paper PDF or scientific implementation is redistributed; the separate paper package retains its publisher typography license.
