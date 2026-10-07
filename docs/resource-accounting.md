# Execution accounting

The resource intake was performed once before scientific work. It found a four-core entitlement, a 4-GiB memory limit, no configured swap, and sufficient writable space. Scientific phase execution was sequential with one worker. No stress test, GPU, external compute, remote model/API, live scan, or private data was used.

## Retained instrumented executions

| Execution | Logical checks | Process CPU seconds | Peak RSS KiB | Evidence |
|---|---:|---:|---:|---|
| Abstract intake | 19590 | 0.019609229 | 92464 | results/intake-abstract.json |
| Retained end-to-end intake | 216 query equalities + 6 negative controls | 0.000776562 | 94124 | results/intake-e2e.json |
| Reference campaign | 82644 | 11.582585051 | 115120 | results/reference/runtime-summary.json |
| Final post-repair clean reproduction | 82644 | 14.203881768 | 115504 | results/clean/runtime-summary.json |

The two complete executions therefore contribute 165,288 counted logical-obligation evaluations. Including the retained abstract and end-to-end intake gives 185,100. An earlier preliminary scaling pass contributed 564 reported obligations before the encoding-matched comparison repair, for a known subtotal of 185,664. Those superseded timings are not used as scientific performance evidence. Development included additional short pilot attempts and regressions; not every transient attempt has a retained per-attempt counter or CPU record. Accordingly, 185,664 is a **known subtotal**, not a falsely exact cumulative-development count. The retained complete-run CPU values are likewise not a whole-development timing claim.


The post-repair clean run records its environment in `results/clean/environment.json`: CPython 3.13.5 (`/opt/pyvenv/bin/python`), x86_64, an Intel Xeon Platinum 8573C exposed to the process, Debian GNU/Linux 13, Linux 6.18.44, inherited affinity CPUs 0--4, and selected CPU 0 for every phase. The execution image identifier was not exposed. The older reference campaign did not retain exact Python, CPU/architecture, OS/image, inherited mask, or selected CPU; `results/reference/environment.json` marks those fields `not recorded` instead of substituting the clean machine.

The post-repair focused regression execution passed 31 tests: 18 interface/contract tests and 13 extremal-construction tests (`results/clean/unit-tests.txt`). These reuse the included input inventory. Tests, timing calls, parsed records, and logical equality assertions are distinct units. Each scaling cut has 2,560 timed query calls; those repetitions are not new cases and are not individually counted as correctness assertions. The full-run logical-obligation counter includes the comparisons actually performed.

That 31-test log is historical. The current suite has 40 tests (19 interface, 15 extremal, and six ancestry-reuse), including invalid-budget handling for empty lists, admissible construction-deadline boundaries, literal DAGs, scale contexts, retained rejections, and call-local/input-cap checks. It passes in a separate Windows execution using CPython 3.12.14. This check does not rerun the Linux resource instrumentation or replace either campaign's timing/RSS values. The prepared scientific workflow is a future Linux execution gate, not a completed run.

## Enforced limits and closure

Each scientific phase sets a 2,500,000,000-byte address-space limit, a 100-second CPU limit, a 120-second wall timeout, and one-core affinity. A whole run refuses more than 85,000 logical checks. Both complete executions have 21 phases and passed within these limits; their combined retained process CPU is 25.786466819 seconds. The input inventory is fixed at 997 entries, with at most 2,000 provenance records per included case. Inputs are generated locally, not downloaded datasets; no scholarly PDF is required or redistributed.

The frozen campaign contains 82,644 distinct programmed obligations, below the 200,000-obligation design ceiling. The clean execution repeats the same obligations for reproducibility rather than enlarging the scientific case set. No additional full scientific campaign is needed unless semantics or implementation changes. A changed theorem, checker, engine, generator, or raw result would require a separately recorded repair and recheck; prose-only packaging changes do not authorize new result claims.

Source downloads and typesetting activity were not fully byte/CPU-metered across all transient browser attempts. The delivered project and exact generated inputs fit the package bounds, but no invented exact total-download or total-development CPU certificate is supplied. This accounting limitation does not alter the exact semantic outcome counts, and it remains an explicit nonclaim.
