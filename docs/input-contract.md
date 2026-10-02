# Input and certificate contract

All consumed scientific inputs are included, generated locally, and covered by the repository license. The data are schema-inspired, not exported from a public service. Acquisition consists of running the deterministic generator and comparing with the included exact bytes. No external scientific dataset is needed.

A prefix is a JSON object with exactly `cut`, `q0`, `policy`, and `events`. The cut is an opaque ASCII identifier. The independent caller must bind it to the actual complete admitted prefix and policy; its spelling has no cryptographic significance. `q0` is an integer lower bound for all future query times, not a wall-clock measurement taken by this artifact.

A policy contains `entities` (1–500 opaque identifiers), `attributes` (1–32), `sources` (1–16), and Boolean `node_scopes`. Each source declares integer priority 0–65535, authorized attributes, a Boolean permission to issue aliases, and distinct revocation scopes. User scopes cannot start with `n:`. When `node_scopes` is true, every observation, derived record, and alias receives its own `n:<id>` token as well. There are at most 4,096 tokens. Scopes represent revocation rights, not probabilities or source truth. A private token may occur in descendants' inherited supports; “private” in the independent-leaf lower bound has the stronger meaning that it is absent from every other candidate's complete support.

There are at most 5,000 events and 2,000 distinct provenance records. Records have `kind`, immutable `id`, `source`, `lo`, `hi`, positive `ttl`, and at most four `parents`. IDs have at most 60 ASCII characters. The local freshness deadline is `lo + ttl`, with `0 <= lo <= hi <= q0 <= 2^31-1` and `1 <= ttl <= 2^31-1`. Queries may reach `2^32-1`; deadlines do not wrap. A Boolean is not an integer in the accepted wire schema.

Observation and derived records additionally contain `entity`, `attribute`, sorted unique `value` (at most 32 integers in 0–65535), and `rule`. Observations use `leaf` with no parents. Derived records use `copy` with one parent, or `union` with one or more parents; all parents share the child's base entity and attribute, and the child value must equal the finite-set union. Every record is independently source-authorized. Parent references must name observation or derived records, never aliases; the full parent graph is acyclic. Inputs need not arrive topologically sorted.

An alias instead contains two different `ends`. All admitted alias edges, including expired/revoked edges, form an undirected forest. Its parents may justify the attestation. A cut whose union creates a cycle or parallel alias is rejected; the engine never chooses a convenient arrival-order-dependent spanning tree. Base entity ownership is immutable.

An event `{ "kind": "revoke", "token": "..." }` places a known scope into the cut's revocation set. Revocation has no reinstatement in this model. An exact record replay is idempotent and cannot refresh age; a different payload with the same ID is invalid. Complete subsequent revocations are provided separately at query time. Unknown tokens, times before `q0`, and a mismatched independently known cut are rejected.

The producer's certificate contains the cut, `q0`, anchor/attribute query, retained frontier summaries, one retained dominator for every other initially eligible candidate, and one reason for every initially inactive candidate. Summary fields are ID, exact rank, inherited deadline, complete support, and unique alias path. Values come from the independently checked prefix, not an unaudited certificate field. Inactive reasons are disconnected, expired, or already revoked. The checker requires a complete disjoint partition, validates every reason and dominator, and checks that retained candidates are mutually undominated.

`check(prefix, certificate, *, expected_entity, expected_attribute)` and `verify(raw, certificate, *, expected_entity, expected_attribute)` require the trusted caller to supply the target independently of the certificate. The checker validates both expected fields against the admitted policy and rejects a certificate whose repeated `query` target differs. The resulting frozen `Verified` object stores `entity` and `attribute` together with the cut and summaries; a same-cut certificate for another target cannot redirect the cache. It is a local verified candidate cache, not a signed remote response, and returns the maximum live ID (and optionally value) only for its stored target. Changes to evidence, the policy, source priorities, scope definitions, alias graph, or reinstatement require a new independently admitted cut and bootstrap.

## Exact case inventory

| File | Entries | Meaning |
|---|---:|---|
| abstract.jsonl | 768 | 576 two-candidate worlds over three tokens and 192 three-candidate worlds over two tokens |
| traces.jsonl | 192 | Six regimes, 32 fixed seeded generated cuts each; two queries and 12 contexts per query |
| scaling.jsonl | 12 | Four sizes through 2,000 records in shared, independent-private, and AND-chain regimes |
| intake.json | 1 | Development cut retained for certificate mutation and clean-control tests |
| invalid-streams.jsonl | 18 | Deliberate schema, authorization, replay, graph, derivation and clock failures |
| valid-controls.jsonl | 6 | Valid counterparts and boundary cases |

Total 997 entries, including 768 abstract models and 229 complete event-stream cases. Certificate mutations and query guards reuse these inputs. No claim of a held-out real-world workload, human study, or model training is made.
