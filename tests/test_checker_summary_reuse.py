"""Portable finite ancestry regressions with a literal scan reference."""
from copy import deepcopy
import csv
from itertools import product
import json
from pathlib import Path
import unittest

from freshcert.checker import AuditError, Prefix, check
from freshcert.engine import Compiled

ROOT = Path(__file__).resolve().parents[1]


def literal_cut(parents, deadlines, scopes, *, private=False):
    return {"cut": "literal-cut", "q0": 1, "policy": {
        "entities": ["e"], "attributes": ["tag"], "node_scopes": private,
        "sources": {
            "clear": {"priority": 0, "attributes": ["tag"], "alias": True, "scopes": []},
            "scoped": {"priority": 1, "attributes": ["tag"], "alias": True, "scopes": ["a"]}}},
        "events": [{"kind": "derive" if deps else "observe", "id": f"n{i}",
            "entity": "e", "attribute": "tag", "value": [1],
            "source": "scoped" if scopes[i] else "clear",
            "lo": 0, "hi": 0, "ttl": deadlines[i], "parents": [f"n{p}" for p in deps],
            "rule": "union" if len(deps) > 1 else "copy" if deps else "leaf"}
            for i, deps in enumerate(parents)]}


def tiny_cuts():
    for n in range(1, 4):
        edges = [(p, c) for c in range(n) for p in range(c)]
        for selected in product((False, True), repeat=len(edges)):
            parents = [[p for (p, c), yes in zip(edges, selected) if yes and c == i]
                       for i in range(n)]
            for deadlines in product((3, 5), repeat=n):
                for scopes in product((False, True), repeat=n):
                    yield literal_cut(parents, deadlines, scopes)


def unpack(raw):
    records = {r["id"]: r for r in raw["events"] if r["kind"] != "revoke"}
    nodes = {k: r for k, r in records.items() if r["kind"] != "alias"}
    known = {r["token"] for r in raw["events"] if r["kind"] == "revoke"}
    adjacency = {e: [] for e in raw["policy"]["entities"]}
    for key, row in records.items():
        if row["kind"] == "alias":
            a, b = row["ends"]
            adjacency[a].append((b, key)); adjacency[b].append((a, key))
    return records, nodes, known, adjacency


def scan_reference(raw, entity, attribute):
    """Enumerate full ancestor sets, never call a compiled reduction."""
    records, nodes, known, adjacency = unpack(raw)
    routes = {entity: ()}
    queue = [entity]
    for here in queue:
        for there, edge in adjacency[here]:
            if there not in routes:
                routes[there] = routes[here] + (edge,)
                queue.append(there)
    active, inactive = {}, {}
    for key, row in nodes.items():
        if row["attribute"] != attribute:
            continue
        if row["entity"] not in routes:
            inactive[key] = "disconnected"; continue
        path = routes[row["entity"]]
        visited, pending = set(), [key, *path]
        while pending:
            current = pending.pop()
            if current not in visited:
                visited.add(current)
                pending.extend(records[current]["parents"])
        deadline = min(records[k]["lo"] + records[k]["ttl"] for k in visited)
        support = {t for k in visited
                   for t in raw["policy"]["sources"][records[k]["source"]]["scopes"]}
        if raw["policy"]["node_scopes"]:
            support.update("n:" + k for k in visited)
        if deadline <= raw["q0"]:
            inactive[key] = "expired"
        elif support & known:
            inactive[key] = "revoked"
        else:
            active[key] = {"identity": key,
                "rank": (raw["policy"]["sources"][row["source"]]["priority"], row["lo"], key),
                "deadline": deadline, "support": frozenset(support),
                "path": path, "value": tuple(row["value"])}
    return active, inactive


def boolean_reference(raw, entity, attribute, clock, revoked):
    """Evaluate local Boolean obligations, not flattened deadlines/supports."""
    records, nodes, known, adjacency = unpack(raw)
    gone = known | set(revoked)
    pending, live = dict(records), {}
    while pending:
        progress = False
        for key, row in list(pending.items()):
            if all(p in live for p in row["parents"]):
                local = clock < row["lo"] + row["ttl"]
                local = local and not gone.intersection(raw["policy"]["sources"][row["source"]]["scopes"])
                local = local and (not raw["policy"]["node_scopes"] or "n:" + key not in gone)
                live[key] = local and all(live[p] for p in row["parents"])
                del pending[key]; progress = True
        assert progress, "Literal oracle requires a valid DAG"
    reached, queue = {entity}, [entity]
    for here in queue:
        for there, edge in adjacency[here]:
            if live[edge] and there not in reached:
                reached.add(there); queue.append(there)
    eligible = [k for k, r in nodes.items()
                if r["attribute"] == attribute and r["entity"] in reached and live[k]]
    best = max(eligible, key=lambda k: (raw["policy"]["sources"][nodes[k]["source"]]["priority"],
                                     nodes[k]["lo"], k), default=None)
    return None if best is None else (best, tuple(nodes[best]["value"]))


def summary_dict(active):
    return {key: {"identity": x.identity, "rank": x.rank, "deadline": x.deadline,
                  "support": x.support, "path": x.path, "value": x.value}
            for key, x in active.items()}


def capture_error(fn):
    try:
        fn()
    except (AuditError, ValueError, TypeError) as exc:
        return {"type": type(exc).__name__, "message": str(exc), "args": exc.args}
    return None


def named_cuts():
    raw = literal_cut([[], [0], [0], [1, 2]], [5, 7, 3, 9], [True, False, True, False])
    yield "and-diamond", raw, "e", "tag"
    private = deepcopy(raw); private["policy"]["node_scopes"] = True
    yield "private-diamond", private, "e", "tag"
    route = deepcopy(raw)
    route["policy"]["entities"] += ["anchor", "outside"]
    route["events"] += [{"kind": "alias", "id": "bridge", "ends": ["anchor", "e"],
        "source": "clear", "lo": 0, "hi": 0, "ttl": 8, "parents": ["n1"]},
        {"kind": "observe", "id": "other", "entity": "outside", "attribute": "tag",
         "value": [1], "source": "clear", "lo": 0, "hi": 0, "ttl": 9,
         "parents": [], "rule": "leaf"}]
    yield "alias-parent-disconnected", route, "anchor", "tag"
    reverse = deepcopy(route); reverse["events"].reverse()
    yield "reverse-order", reverse, "anchor", "tag"
    replay = deepcopy(route); replay["events"] += deepcopy(route["events"])
    yield "exact-replays", replay, "anchor", "tag"
    known = deepcopy(route); known["events"].append({"kind": "revoke", "token": "a"})
    yield "known-revocation", known, "anchor", "tag"
    expired = deepcopy(route); expired["events"][0]["ttl"] = 1
    yield "expired-ancestry", expired, "anchor", "tag"
    other = deepcopy(route)
    other["policy"]["attributes"].append("other")
    for src in other["policy"]["sources"].values():
        src["attributes"].append("other")
    other["events"][-1]["attribute"] = "other"
    yield "other-attribute", other, "anchor", "other"


def boundary_cuts():
    one = literal_cut([[]], [3], [False])
    events = deepcopy(one); events["events"] *= 5000
    yield "events-5000", events, True
    too_many = deepcopy(events); too_many["events"].append(deepcopy(one["events"][0]))
    yield "events-5001", too_many, False
    for n in (2000, 2001):
        yield f"records-{n}", literal_cut([[] for _ in range(n)], [3] * n, [False] * n), n == 2000
    for n in (4, 5):
        yield f"parents-{n}", literal_cut([[] for _ in range(n)] + [list(range(n))],
                                        [3] * (n + 1), [False] * (n + 1)), n == 4
    for n in (4096, 4097):
        tokens = deepcopy(one)
        tokens["policy"]["sources"]["clear"]["scopes"] = [f"t{i}" for i in range(n - 1)]
        yield f"tokens-{n}", tokens, n == 4096


class SummaryReuse(unittest.TestCase):
    def assert_fixture(self, raw, entity, attribute, contexts):
        unchanged = deepcopy(raw)
        prefix = Prefix(raw)
        active, inactive = prefix.summaries(entity, attribute)
        reference, rejected = scan_reference(raw, entity, attribute)
        self.assertEqual(summary_dict(active), reference)
        self.assertEqual(list(active), list(reference))
        self.assertEqual(list(inactive.items()), list(rejected.items()))
        cert = Compiled(raw).certificate(entity, attribute)
        cache = check(prefix, cert, expected_entity=entity, expected_attribute=attribute)
        for clock, revoked in contexts:
            expected = boolean_reference(raw, entity, attribute, clock, revoked)
            self.assertEqual(cache.record(clock, revoked, current_cut=raw["cut"]), expected)
            self.assertEqual(prefix.direct(entity, attribute, clock, revoked),
                             None if expected is None else expected[0])
        self.assertEqual(raw, unchanged)

    def test_complete_literal_tiny_dag_domain(self):
        count = 0
        for raw in tiny_cuts():
            self.assert_fixture(raw, "e", "tag", product((1, 2, 3, 4, 5), ((), ("a",))))
            count += 1
        self.assertEqual(count, 548)

    def test_named_shared_ancestry_alias_and_replay_cases(self):
        for name, raw, entity, attribute in named_cuts():
            with self.subTest(name=name):
                scopes = {t for row in raw["policy"]["sources"].values() for t in row["scopes"]}
                if raw["policy"]["node_scopes"]:
                    scopes.add("n:n0")
                self.assert_fixture(raw, entity, attribute,
                    product((1, 2, 3, 4, 5, 8, 9), ((), tuple(sorted(scopes)))))

    def test_all_prescribed_scale_contexts_and_retained_answers(self):
        rows = [json.loads(line) for line in (ROOT / "inputs/scaling.jsonl").read_text().splitlines()]
        self.assertEqual(len(rows), 12)
        contexts = 0
        for i, case in enumerate(rows):
            spec = case["queries"][0]
            pairs = [(x["q"], x["revoked"]) for x in spec["contexts"]]
            self.assert_fixture(case["stream"], spec["entity"], spec["attribute"], pairs)
            with (ROOT / f"results/reference/scale-{i:02d}-queries.csv").open(newline="") as f:
                retained = list(csv.DictReader(f))
            cache = check(Prefix(case["stream"]),
                Compiled(case["stream"]).certificate(spec["entity"], spec["attribute"]),
                expected_entity=spec["entity"], expected_attribute=spec["attribute"])
            self.assertEqual(len(retained), len(pairs))
            for row, (q, revoked) in zip(retained, pairs):
                identity = cache.query(q, revoked, current_cut=case["stream"]["cut"]) or ""
                self.assertEqual({row[k] for k in ("expected", "verified", "full_compiled", "full_set_cache")},
                                 {identity})
            contexts += len(pairs)
        self.assertEqual(contexts, 192)

    def test_retained_rejections_and_valid_controls(self):
        with (ROOT / "results/reference/faults.csv").open(newline="") as f:
            retained = {(r["case"], r["method"]): r for r in csv.DictReader(f)}
        invalid = [json.loads(x) for x in (ROOT / "inputs/invalid-streams.jsonl").read_text().splitlines()]
        self.assertEqual(len(invalid), 18)
        for case in invalid:
            for method, fn in (("checker", Prefix), ("producer", Compiled)):
                error = capture_error(lambda: fn(case["stream"]))
                self.assertIsNotNone(error)
                self.assertEqual(error["message"], retained[case["id"], method]["reason"])
        intake = json.loads((ROOT / "inputs/intake.json").read_text())
        prefix = Prefix(intake)
        mutations = [json.loads(x) for x in
                     (ROOT / "results/reference/certificate-mutations.jsonl").read_text().splitlines()]
        self.assertEqual(len(mutations), 20)
        for mutation in mutations:
            error = capture_error(lambda: check(prefix, mutation["certificate"],
                expected_entity="e0", expected_attribute="tag"))
            self.assertIsNotNone(error)
            self.assertEqual(error["message"], retained[mutation["case"], "checker"]["reason"])
        cache = check(prefix, Compiled(intake).certificate("e0", "tag"),
                      expected_entity="e0", expected_attribute="tag")
        for name, q, revoked, cut in (("cut", 6, [], "unrelated-cut"),
            ("past-time", 4, [], intake["cut"]), ("unknown-scope", 6, ["missing"], intake["cut"]),
            ("boolean-time", True, [], intake["cut"])):
            error = capture_error(lambda: cache.query(q, revoked, current_cut=cut))
            self.assertIsNotNone(error)
            self.assertEqual(error["message"], retained["guard-" + name, "checker"]["reason"])
        valid = [json.loads(x) for x in (ROOT / "inputs/valid-controls.jsonl").read_text().splitlines()]
        self.assertEqual(len(valid), 6)
        for case in valid:
            self.assert_fixture(case["stream"], "e0", "tag",
                ((q, tuple(t for i, t in enumerate(("a", "b", "link")) if mask >> i & 1))
                 for q, mask in product(range(5, 32), range(8))))

    def test_memo_is_call_local_and_input_is_not_mutated(self):
        raw = literal_cut([[], [0]], [3, 5], [True, False])
        prefix = Prefix(raw)
        original_attributes = set(vars(prefix))
        original = deepcopy(vars(prefix))
        prefix.summaries("e", "tag")
        self.assertEqual(vars(prefix), original)
        self.assertEqual(set(vars(prefix)), original_attributes)
        prefix.records["n0"]["ttl"] = 6
        altered = deepcopy(raw); altered["events"][0]["ttl"] = 6
        self.assertEqual(summary_dict(prefix.summaries("e", "tag")[0]), scan_reference(altered, "e", "tag")[0])
        prefix.policy["sources"]["scoped"]["scopes"] = []
        altered["policy"]["sources"]["scoped"]["scopes"] = []
        self.assertEqual(summary_dict(prefix.summaries("e", "tag")[0]), scan_reference(altered, "e", "tag")[0])

    def test_private_support_growth_and_fixed_width_boundaries(self):
        raw = literal_cut([[]] + [[i - 1] for i in range(1, 128)],
                          [5] * 128, [False] * 128, private=True)
        self.assert_fixture(raw, "e", "tag", product((1, 4, 5), ((), ("n:n0",), ("n:n127",))))
        prefix = Prefix(raw)
        self.assertEqual(len(prefix.summaries("e", "tag")[0]["n127"].support), 128)
        maximum = literal_cut([[], [0]], [2**31 - 1] * 2, [False, True])
        maximum["q0"] = 2**31 - 1
        for row in maximum["events"]:
            row["lo"] = row["hi"] = 2**31 - 1
        self.assert_fixture(maximum, "e", "tag",
            product((2**31 - 1, 2**32 - 3, 2**32 - 2, 2**32 - 1), ((), ("a",))))
        for name, raw, accepted in boundary_cuts():
            with self.subTest(boundary=name):
                if accepted:
                    self.assert_fixture(raw, "e", "tag", ((1, ()), (2, ()), (3, ())))
                else:
                    self.assertIsNotNone(capture_error(lambda: Prefix(raw)))
                    self.assertIsNotNone(capture_error(lambda: Compiled(raw)))


if __name__ == "__main__":
    unittest.main()
