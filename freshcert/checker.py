"""Independent certificate checker and direct Boolean replay oracle.

Does not import engine.py or frontier.py. Input is an independently obtained,
complete admitted prefix and its fixed policy, not a prefix supplied only by a
potentially dishonest certificate producer. No cryptographic authentication is
implemented. Record IDs name immutable evidence, not network hosts.
"""
from dataclasses import dataclass
from copy import deepcopy

class AuditError(ValueError):
    """A located schema, derivation, graph, or certificate violation."""

def insist(condition, reason):
    if not condition:
        raise AuditError(reason)

def natural(x, low=0, high=2**31-1):
    return type(x) is int and low <= x <= high

def text(x):
    return type(x) is str and 1 <= len(x) <= 80 and x.isascii()

def names(xs):
    return type(xs) is list and all(text(x) for x in xs) and len(set(xs)) == len(xs)

@dataclass(frozen=True)
class Summary:
    identity: str
    rank: tuple
    deadline: int
    support: frozenset
    path: tuple
    value: tuple

@dataclass(frozen=True)
class Verified:
    cut: str
    q0: int
    entity: str
    attribute: str
    tokens: frozenset
    entries: tuple[Summary, ...]

    def query(self, clock, revoked=(), *, current_cut):
        insist(type(current_cut) is str and current_cut == self.cut, "query.cut: stale verified cache")
        insist(natural(clock, self.q0, 2**32-1), 'query.clock: outside cut/fixed-width domain')
        insist(type(revoked) in {tuple, list, set, frozenset} and all(text(x) for x in revoked), 'query.revoked: token list')
        revoked = frozenset(revoked)
        insist(revoked <= self.tokens, 'query.revoked: unknown policy token')
        best = None
        for x in self.entries:
            if clock < x.deadline and x.support.isdisjoint(revoked):
                if best is None or x.rank > best.rank:
                    best = x
        return None if best is None else best.identity

    def record(self, clock, revoked=(), *, current_cut):
        identity = self.query(clock, revoked, current_cut=current_cut)
        return next(((x.identity, x.value) for x in self.entries if x.identity == identity), None)

class Prefix:
    """Separately validated evidence, with a direct per-context Boolean oracle."""
    def __init__(self, raw):
        try:
            self._read(deepcopy(raw))
        except (KeyError, TypeError, AttributeError, IndexError) as exc:
            raise AuditError('prefix: malformed field type or missing field') from exc

    def _read(self, raw):
        insist(type(raw) is dict and set(raw) == {'cut', 'q0', 'policy', 'events'}, 'prefix.fields')
        insist(text(raw['cut']) and natural(raw['q0']), 'prefix.cut/clock')
        p = raw['policy']
        insist(type(p) is dict and set(p) == {'entities', 'attributes', 'sources', 'node_scopes'}, 'policy.fields')
        insist(names(p['entities']) and 1 <= len(p['entities']) <= 500, 'policy.entities')
        insist(names(p['attributes']) and 1 <= len(p['attributes']) <= 32, 'policy.attributes')
        insist(type(p['node_scopes']) is bool, 'policy.node_scopes')
        registry = p['sources']
        insist(type(registry) is dict and 1 <= len(registry) <= 16, 'policy.sources')
        universe = set()
        for source, row in registry.items():
            insist(text(source) and type(row) is dict and set(row) == {'priority', 'attributes', 'alias', 'scopes'}, 'policy.source.fields')
            insist(natural(row['priority'], 0, 65535) and names(row['attributes']) and set(row['attributes']) <= set(p['attributes']), 'policy.source.authorization')
            insist(type(row['alias']) is bool and names(row['scopes']) and all(not s.startswith('n:') for s in row['scopes']), 'policy.source.scopes')
            universe.update(row['scopes'])
        insist(type(raw['events']) is list and len(raw['events']) <= 5000, 'prefix.events')
        nodes, aliases, known = {}, {}, set()
        for row in raw['events']:
            insist(type(row) is dict, 'event.object')
            kind = row.get('kind')
            if kind == 'revoke':
                insist(set(row) == {'kind', 'token'} and text(row['token']), 'revoke.fields')
                known.add(row['token']); continue
            base = {'kind', 'id', 'source', 'lo', 'hi', 'ttl', 'parents'}
            insist(kind in {'alias', 'observe', 'derive'}, 'event.kind')
            required = base | ({'ends'} if kind == 'alias' else {'entity', 'attribute', 'value', 'rule'})
            insist(set(row) == required and text(row['id']) and len(row['id']) <= 60 and row['source'] in registry, 'record.fields/identity')
            insist(natural(row['lo']) and natural(row['hi']) and row['lo'] <= row['hi'] <= raw['q0'] and natural(row['ttl'], 1), 'record.clock')
            insist(names(row['parents']) and len(row['parents']) <= 4, 'record.parents')
            auth = registry[row['source']]
            if kind == 'alias':
                insist(type(row['ends']) is list and len(row['ends']) == 2 and row['ends'][0] != row['ends'][1] and all(e in p['entities'] for e in row['ends']), 'alias.endpoints')
                insist(auth['alias'], 'alias.authorization')
            else:
                insist(row['entity'] in p['entities'] and row['attribute'] in auth['attributes'], 'node.authorization')
                value = row['value']
                insist(type(value) is list and len(value) <= 32 and all(natural(v, 0, 65535) for v in value) and value == sorted(set(value)), 'node.value')
                if kind == 'observe':
                    insist(row['rule'] == 'leaf' and row['parents'] == [], 'observe.rule')
                else:
                    insist(row['rule'] in {'copy', 'union'} and len(row['parents']) > 0 and (row['rule'] != 'copy' or len(row['parents']) == 1), 'derive.rule')
            previous = nodes.get(row['id'], aliases.get(row['id']))
            insist(previous is None or previous == row, 'record.conflicting_replay')
            (aliases if kind == 'alias' else nodes)[row['id']] = row
        records = {**nodes, **aliases}
        insist(len(records) <= 2000, 'prefix.node_bound')
        if p['node_scopes']:
            universe.update('n:' + key for key in records)
        insist(len(universe) <= 4096 and known <= universe, 'revoke.unknown_scope')
        for key, row in records.items():
            insist(all(parent in nodes for parent in row['parents']), 'parent.missing_or_alias:' + key)
        # Depth-first three-colour validation differs from the producer's queue.
        colour, order = {}, []
        for start in sorted(records):
            stack = [(start, False)]
            while stack:
                key, leaving = stack.pop()
                if leaving:
                    colour[key] = 2; order.append(key); continue
                state = colour.get(key, 0)
                if state == 2:
                    continue
                insist(state != 1, 'parent.cycle:' + key)
                colour[key] = 1
                stack.append((key, True))
                for parent in reversed(records[key]['parents']):
                    insist(colour.get(parent, 0) != 1, 'parent.cycle:' + key)
                    if colour.get(parent, 0) == 0:
                        stack.append((parent, False))
        for key in order:
            row = records[key]
            if row['kind'] == 'derive':
                expected = set()
                for parent in row['parents']:
                    dep = nodes[parent]
                    insist((dep['entity'], dep['attribute']) == (row['entity'], row['attribute']), 'derive.domain:' + key)
                    expected.update(dep['value'])
                insist(sorted(expected) == row['value'], 'derive.value:' + key)
        adjacency = {e: [] for e in p['entities']}
        for key, row in aliases.items():
            a, b = row['ends']; adjacency[a].append((b, key)); adjacency[b].append((a, key))
        visited = set()
        for start in p['entities']:
            if start in visited:
                continue
            stack = [(start, None)]
            while stack:
                here, incoming = stack.pop()
                insist(here not in visited, 'alias.cycle')
                visited.add(here)
                for there, edge in adjacency[here]:
                    if edge != incoming:
                        stack.append((there, edge))
        self.cut, self.q0, self.policy = raw['cut'], raw['q0'], p
        self.nodes, self.aliases, self.records = nodes, aliases, records
        self.tokens, self.known, self.order, self.adj = frozenset(universe), frozenset(known), tuple(order), adjacency

    def summaries(self, entity, attribute):
        insist(entity in self.policy['entities'] and attribute in self.policy['attributes'], 'query.domain')
        # Reconstruct from admitted records, with reductions local to this call.
        routes = {entity: ()}; stack = [entity]
        while stack:
            here = stack.pop()
            for there, edge in self.adj[here]:
                if there not in routes:
                    routes[there] = routes[here] + (edge,); stack.append(there)
        ancestry = {}
        def reduce_ancestry(start):
            pending = [(start, False)]
            while pending:
                current, leaving = pending.pop()
                if current in ancestry:
                    continue
                record = self.records[current]
                if not leaving:
                    pending.append((current, True))
                    pending.extend((parent, False) for parent in record['parents']
                                   if parent not in ancestry)
                    continue
                d = record['lo'] + record['ttl']
                support = set(self.policy['sources'][record['source']]['scopes'])
                if self.policy['node_scopes']:
                    support.add('n:' + current)
                for parent in record['parents']:
                    pd, ps = ancestry[parent]
                    d = min(d, pd); support.update(ps)
                ancestry[current] = (d, frozenset(support))
            return ancestry[start]
        active, inactive = {}, {}
        for key, row in self.nodes.items():
            if row['attribute'] != attribute:
                continue
            if row['entity'] not in routes:
                inactive[key] = 'disconnected'; continue
            path = routes[row['entity']]
            d, own_support = reduce_ancestry(key)
            support = set(own_support)
            for edge in path:
                ed, es = reduce_ancestry(edge)
                d = min(d, ed); support.update(es)
            if d <= self.q0:
                inactive[key] = 'expired'
            elif not support.isdisjoint(self.known):
                inactive[key] = 'revoked'
            else:
                active[key] = Summary(key, (self.policy['sources'][row['source']]['priority'], row['lo'], key),
                                      d, frozenset(support), path, tuple(row['value']))
        return active, inactive

    def direct(self, entity, attribute, clock, revoked=(), *, details=False):
        """Evaluate each local predicate and each edge; no flattened summaries."""
        insist(entity in self.policy['entities'] and attribute in self.policy['attributes'], 'query.domain')
        insist(natural(clock, self.q0, 2**32-1), 'query.clock')
        revoked = frozenset(revoked)
        insist(revoked <= self.tokens, 'query.scope')
        gone = revoked | self.known
        live = {}
        for key in self.order:
            row = self.records[key]
            local = clock < row['lo'] + row['ttl']
            local = local and gone.isdisjoint(self.policy['sources'][row['source']]['scopes'])
            local = local and (not self.policy['node_scopes'] or 'n:' + key not in gone)
            live[key] = local and all(live[parent] for parent in row['parents'])
        reached, stack = {entity}, [entity]
        while stack:
            here = stack.pop()
            for there, edge in self.adj[here]:
                if live[edge] and there not in reached:
                    reached.add(there); stack.append(there)
        winner, rank, eligible = None, None, []
        for key, row in self.nodes.items():
            if row['attribute'] == attribute and row['entity'] in reached and live[key]:
                eligible.append(key)
                current = (self.policy['sources'][row['source']]['priority'], row['lo'], key)
                if rank is None or current > rank:
                    winner, rank = key, current
        return (winner, tuple(eligible)) if details else winner

def check(prefix: Prefix, cert, *, expected_entity, expected_attribute) -> Verified:
    """Check one bootstrap certificate for a caller-selected target.

    ``expected_entity`` and ``expected_attribute`` are trusted request inputs; the
    certificate may repeat them but may not select or redirect the query target.
    """
    try:
        insist(text(expected_entity) and expected_entity in prefix.policy['entities'], 'expected.entity')
        insist(text(expected_attribute) and expected_attribute in prefix.policy['attributes'], 'expected.attribute')
        insist(type(cert) is dict and set(cert) == {'cut', 'q0', 'query', 'frontier', 'covered', 'inactive'}, 'certificate.fields')
        insist(type(cert['cut']) is str and cert['cut'] == prefix.cut and type(cert['q0']) is int and cert['q0'] == prefix.q0, 'certificate.cut')
        q = cert['query']
        insist(type(q) is dict and set(q) == {'entity', 'attribute'}, 'certificate.query')
        insist(q['entity'] == expected_entity and q['attribute'] == expected_attribute,
               'certificate.query_target')
        active, inactive = prefix.summaries(expected_entity, expected_attribute)
        kept, partition = {}, set()
        insist(type(cert['frontier']) is list and type(cert['covered']) is list and type(cert['inactive']) is list, 'certificate.lists')
        for row in cert['frontier']:
            insist(type(row) is dict and set(row) == {'id', 'rank', 'deadline', 'support', 'path'}, 'frontier.fields')
            key = row['id']
            insist(text(key) and key in active and key not in partition, 'frontier.identity')
            x = active[key]
            insist(type(row['rank']) is list and len(row['rank']) == 3 and natural(row['rank'][0], 0, 65535) and natural(row['rank'][1]) and text(row['rank'][2]) and tuple(row['rank']) == x.rank, 'frontier.rank:' + key)
            insist(natural(row['deadline'], 1, 2**32-2) and row['deadline'] == x.deadline, 'frontier.deadline:' + key)
            insist(names(row['support']) and frozenset(row['support']) == x.support, 'frontier.support:' + key)
            insist(names(row['path']) and tuple(row['path']) == x.path, 'frontier.path:' + key)
            kept[key] = x; partition.add(key)
        def covers(y, x):
            return y.rank > x.rank and y.deadline >= x.deadline and y.support <= x.support
        for x in kept.values():
            insist(not any(covers(y, x) for y in kept.values()), 'frontier.redundancy:' + x.identity)
        for row in cert['covered']:
            insist(type(row) is dict and set(row) == {'id', 'by'}, 'cover.fields')
            key, witness = row['id'], row['by']
            insist(text(key) and text(witness) and key in active and key not in partition and witness in kept, 'cover.identity')
            insist(covers(kept[witness], active[key]), 'cover.invalid:' + key)
            partition.add(key)
        insist(partition == set(active), 'cover.omitted_active_candidate')
        seen_inactive = set()
        for row in cert['inactive']:
            insist(type(row) is dict and set(row) == {'id', 'reason'}, 'inactive.fields')
            key = row['id']
            insist(text(key) and key in inactive and key not in seen_inactive and row['reason'] == inactive[key], 'inactive.reason')
            seen_inactive.add(key)
        insist(seen_inactive == set(inactive), 'inactive.omitted_candidate')
        return Verified(prefix.cut, prefix.q0, expected_entity, expected_attribute, prefix.tokens, tuple(kept.values()))
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        raise AuditError('certificate: malformed field type or missing field') from exc

def verify(raw, cert, *, expected_entity, expected_attribute):
    return check(Prefix(raw), cert, expected_entity=expected_entity,
                 expected_attribute=expected_attribute)
