"""Batch compiler for one complete admitted cut. No network or cryptographic claim."""
from collections import deque
from copy import deepcopy
from .frontier import Candidate, dominates, frontier, query

LIMIT = (1 << 31) - 1

class InvalidStream(ValueError):
    pass

def require(condition, reason):
    if not condition:
        raise InvalidStream(reason)

def integer(value, lower=0, upper=LIMIT):
    return type(value) is int and lower <= value <= upper

def name(value):
    return isinstance(value, str) and 0 < len(value) <= 80 and value.isascii()

def canonical_set(value):
    return isinstance(value, list) and all(name(x) for x in value) and len(value) == len(set(value))

class Compiled:
    def __init__(self, raw):
        try:
            self._read(deepcopy(raw))
        except (KeyError, TypeError, AttributeError, IndexError) as exc:
            raise InvalidStream("malformed field type or missing field") from exc

    def _read(self, raw):
        require(isinstance(raw, dict) and set(raw) == {'cut', 'q0', 'policy', 'events'}, 'top-level fields')
        require(name(raw['cut']) and integer(raw['q0']), 'cut or clock')
        p = raw['policy']
        require(isinstance(p, dict) and set(p) == {'entities', 'attributes', 'sources', 'node_scopes'}, 'policy fields')
        require(canonical_set(p['entities']) and 1 <= len(p['entities']) <= 500, 'entities')
        require(canonical_set(p['attributes']) and 1 <= len(p['attributes']) <= 32, 'attributes')
        require(type(p['node_scopes']) is bool, 'node scope policy')
        sources = p['sources']
        require(isinstance(sources, dict) and 1 <= len(sources) <= 16, 'source classes')
        for k, s in sources.items():
            require(name(k) and isinstance(s, dict) and set(s) == {'priority', 'attributes', 'alias', 'scopes'}, 'source fields')
            require(integer(s['priority'], 0, 65535) and canonical_set(s['attributes']) and set(s['attributes']) <= set(p['attributes']), 'source attributes/priority')
            require(type(s['alias']) is bool and canonical_set(s['scopes']), 'source scopes/alias')
            require(all(not t.startswith('n:') for t in s['scopes']), 'reserved token prefix')
        events = raw['events']
        require(isinstance(events, list) and len(events) <= 5000, 'event count')
        records, revoke = {}, set()
        for ev in events:
            require(isinstance(ev, dict), 'event type')
            kind = ev.get('kind')
            if kind == 'revoke':
                require(set(ev) == {'kind', 'token'} and name(ev['token']), 'revoke fields')
                revoke.add(ev['token']); continue
            common = {'kind', 'id', 'source', 'lo', 'hi', 'ttl', 'parents'}
            fields = common | ({'ends'} if kind == 'alias' else {'entity', 'attribute', 'value', 'rule'})
            require(kind in {'observe', 'derive', 'alias'} and set(ev) == fields, 'record fields')
            require(name(ev['id']) and len(ev['id']) <= 60 and ev['source'] in sources, 'record identity/source')
            for f in ('lo', 'hi'):
                require(integer(ev[f]), 'timestamp')
            require(ev['lo'] <= ev['hi'] <= raw['q0'] and integer(ev['ttl'], 1), 'timestamp interval / ttl')
            require(canonical_set(ev['parents']) and len(ev['parents']) <= 4, 'parents')
            src = sources[ev['source']]
            if kind == 'alias':
                require(isinstance(ev['ends'], list) and len(ev['ends']) == 2 and all(e in p['entities'] for e in ev['ends']) and ev['ends'][0] != ev['ends'][1], 'alias endpoints')
                require(src['alias'], 'unauthorized alias')
            else:
                require(ev['entity'] in p['entities'] and ev['attribute'] in src['attributes'], 'unauthorized attribute')
                require(isinstance(ev['value'], list) and len(ev['value']) <= 32 and all(integer(v, 0, 65535) for v in ev['value']) and ev['value'] == sorted(set(ev['value'])), 'value')
                require(ev['rule'] in {'leaf', 'copy', 'union'}, 'rule')
                require((kind == 'observe' and ev['rule'] == 'leaf' and not ev['parents']) or
                        (kind == 'derive' and ev['rule'] != 'leaf' and bool(ev['parents'])), 'rule arity')
                require(ev['rule'] != 'copy' or len(ev['parents']) == 1, 'copy arity')
            old = records.get(ev['id'])
            require(old is None or old == ev, 'conflicting replay')
            records[ev['id']] = ev
        require(len(records) <= 2000, 'provenance node count')
        self.nodes = {k: v for k, v in records.items() if v['kind'] != 'alias'}
        self.aliases = {k: v for k, v in records.items() if v['kind'] == 'alias'}
        for ev in records.values():
            require(all(x in self.nodes for x in ev['parents']), 'missing/non-node parent')
        tokens = {t for s in sources.values() for t in s['scopes']}
        if p['node_scopes']:
            tokens.update('n:' + k for k in records)
        require(len(tokens) <= 4096 and revoke <= tokens, 'unknown/excess revocation token')
        self.tokens = tuple(sorted(tokens)); self.index = {x: i for i, x in enumerate(self.tokens)}
        self.known = self.mask(revoke)
        self.deadline, self.support = {}, {}
        degree = {k: len(v['parents']) for k, v in records.items()}
        children = {k: [] for k in records}
        for k, v in records.items():
            for parent in v['parents']:
                children[parent].append(k)
        queue = deque(sorted(k for k in degree if degree[k] == 0))
        while queue:
            k = queue.popleft(); ev = records[k]
            parents = ev['parents']
            if ev['kind'] == 'derive':
                require(all(self.nodes[j]['entity'] == ev['entity'] and self.nodes[j]['attribute'] == ev['attribute'] for j in parents), 'derive domain')
                value = sorted({a for j in parents for a in self.nodes[j]['value']})
                require(value == ev['value'], 'derived value')
            d = ev['lo'] + ev['ttl']
            s = self.mask(sources[ev['source']]['scopes'])
            if p['node_scopes']:
                s |= 1 << self.index['n:' + k]
            for j in parents:
                d = min(d, self.deadline[j]); s |= self.support[j]
            self.deadline[k], self.support[k] = d, s
            for child in children[k]:
                degree[child] -= 1
                if degree[child] == 0:
                    queue.append(child)
        require(len(self.deadline) == len(records), 'derivation cycle')
        representative = {e: e for e in p['entities']}
        def root(e):
            while representative[e] != e:
                e = representative[e]
            return e
        self.adj = {e: [] for e in p['entities']}
        for k, ev in sorted(self.aliases.items()):
            a, b = ev['ends']; ra, rb = root(a), root(b)
            require(ra != rb, 'alias cycle')
            representative[ra] = rb
            self.adj[a].append((b, k)); self.adj[b].append((a, k))
        self.raw, self.policy = raw, p
        self.q0, self.cut = raw['q0'], raw['cut']

    def mask(self, tokens):
        out = 0
        for token in tokens:
            require(token in self.index, 'unknown token')
            out |= 1 << self.index[token]
        return out

    def summaries(self, entity, attribute):
        require(entity in self.policy['entities'] and attribute in self.policy['attributes'], 'query domain')
        paths = {entity: ((1 << 32) - 1, 0, ())}
        todo = deque([entity])
        while todo:
            here = todo.popleft(); d, s, path = paths[here]
            for there, edge in self.adj[here]:
                if there not in paths:
                    paths[there] = (min(d, self.deadline[edge]), s | self.support[edge], path + (edge,))
                    todo.append(there)
        active, inactive = [], {}
        for k, ev in self.nodes.items():
            if ev['attribute'] != attribute:
                continue
            if ev['entity'] not in paths:
                inactive[k] = 'disconnected'; continue
            pd, ps, path = paths[ev['entity']]
            d, s = min(pd, self.deadline[k]), ps | self.support[k]
            if d <= self.q0:
                inactive[k] = 'expired'; continue
            if s & self.known:
                inactive[k] = 'revoked'; continue
            rank = (self.policy['sources'][ev['source']]['priority'], ev['lo'], k)
            active.append(Candidate(k, rank, d, s, path))
        return tuple(active), inactive

    def certificate(self, entity, attribute):
        active, inactive = self.summaries(entity, attribute)
        keep = frontier(active); kept_ids = {x.identity for x in keep}
        entries = [{'id': x.identity, 'rank': list(x.rank), 'deadline': x.deadline,
                    'support': [t for i, t in enumerate(self.tokens) if x.support >> i & 1],
                    'path': list(x.path)} for x in keep]
        covered = [{'id': x.identity, 'by': next(y.identity for y in keep if dominates(y, x))}
                   for x in sorted(active, key=lambda x: x.identity) if x.identity not in kept_ids]
        return {'cut': self.cut, 'q0': self.q0, 'query': {'entity': entity, 'attribute': attribute},
                'frontier': entries, 'covered': covered,
                'inactive': [{'id': k, 'reason': v} for k, v in sorted(inactive.items())]}
