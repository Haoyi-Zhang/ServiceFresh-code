"""Frozen, generated-only cases. Never connects to a network or reads user data."""
import json
import random
from copy import deepcopy
from itertools import product
from pathlib import Path

REGIMES = ('mixed', 'and-dependency', 'alias-chain', 'replay-order', 'clock-interval', 'private-scopes')

def node(identity, entity, attribute, source, lo, hi, ttl, value, parents=(), rule=None):
    return {'kind': 'derive' if parents else 'observe', 'id': identity, 'entity': entity,
            'attribute': attribute, 'source': source, 'lo': lo, 'hi': hi, 'ttl': ttl,
            'value': sorted(set(value)), 'parents': list(parents),
            'rule': rule or ('copy' if len(parents) == 1 else 'union' if parents else 'leaf')}

def policy(entities, attributes, private=False):
    return {'entities': entities, 'attributes': attributes, 'node_scopes': private,
            'sources': {f's{i}': {'priority': i, 'attributes': list(attributes), 'alias': i == 3,
                                 'scopes': [f'scope:{i}']} for i in range(4)}}

def abstract_cases():
    number = 0
    for supports in product(range(8), repeat=2):
        for deadlines in product(range(1, 4), repeat=2):
            yield {'id': f'abstract-{number:03d}', 'tokens': 3, 'deadlines': list(deadlines), 'supports': list(supports)}
            number += 1
    for supports in product(range(4), repeat=3):
        for deadlines in ((1, 1, 1), (1, 2, 3), (3, 2, 1)):
            yield {'id': f'abstract-{number:03d}', 'tokens': 2, 'deadlines': list(deadlines), 'supports': list(supports)}
            number += 1

def trace_case(index):
    regime = REGIMES[index // 32]
    seed = 20260914 + 104729 * index
    rng = random.Random(seed)
    n = 128 if regime == 'and-dependency' else 96 if regime in {'alias-chain', 'clock-interval'} else 64
    entity_count = 2 if regime == 'and-dependency' else 16 if regime == 'alias-chain' else 8
    entities = [f'entity-{i:03d}' for i in range(entity_count)]
    attrs = ['service.family', 'service.label']
    p = policy(entities, attrs, regime == 'private-scopes')
    events, pools = [], {(e, a): [] for e in entities for a in attrs}
    for i in range(n):
        e, a = entities[i % entity_count], attrs[(i // entity_count) % 2]
        source = f's{rng.randrange(4)}'
        lo = rng.randrange(80, 101)
        hi = rng.randrange(lo, 101) if regime == 'clock-interval' else lo
        ttl = rng.randrange(10, 81)
        prior = pools[e, a]
        probability = .85 if regime == 'and-dependency' else .25 if regime != 'private-scopes' else 0
        parents = []
        if prior and rng.random() < probability:
            if regime == 'and-dependency':
                parents = [prior[-1]]
                if len(prior) > 2 and rng.random() < .4:
                    parents.append(prior[rng.randrange(len(prior)-1)])
            else:
                parents = rng.sample(prior[-16:], min(len(prior), rng.choice([1, 1, 2, 3])))
        value = sorted({x for v in parents for x in v['value']}) if parents else [rng.randrange(8)]
        rec = node(f'node-{i:04d}', e, a, source, lo, hi, ttl, value, [x['id'] for x in parents])
        events.append(rec); prior.append(rec)
    for i in range(1, entity_count):
        left = entities[i-1] if regime == 'alias-chain' else entities[0]
        # Forest aliases use authorized attestations. An occasional observation
        # parent makes alias validity depend on recorded evidence as well.
        parents = [events[i % n]['id']] if index % 4 == 0 and i % 3 == 0 else []
        events.append({'kind': 'alias', 'id': f'edge-{i:03d}', 'source': 's3', 'lo': 90, 'hi': 95,
                       'ttl': 45 + rng.randrange(36), 'parents': parents, 'ends': [left, entities[i]]})
    if regime == 'replay-order':
        events.extend(deepcopy(x) for x in rng.sample(events, 16))
        rng.shuffle(events)
    # Some valid cuts already contain a known revocation. This is fixed by index,
    # not selected after observing an output or compression ratio.
    if index % 11 == 0:
        events.append({'kind': 'revoke', 'token': 'scope:0'})
    raw = {'cut': f'trace-{index:03d}', 'q0': 100, 'policy': p, 'events': events}
    token_set = {f'scope:{i}' for i in range(4)}
    if p['node_scopes']:
        token_set.update('n:' + row['id'] for row in events if row['kind'] != 'revoke')
    tokens = sorted(token_set)
    qrng = random.Random(seed + 1_000_003)
    contexts = [
        {'q': 100, 'revoked': []}, {'q': 100, 'revoked': ['scope:0']},
        {'q': 101, 'revoked': ['scope:3']}, {'q': 108, 'revoked': ['scope:0', 'scope:1']},
        {'q': 116, 'revoked': []}, {'q': 132, 'revoked': []},
        {'q': 164, 'revoked': []}, {'q': 228, 'revoked': []},
        {'q': 100, 'revoked': sorted(qrng.sample(tokens, 1))},
        {'q': 104, 'revoked': sorted(qrng.sample(tokens, 2))},
        {'q': 124, 'revoked': sorted(qrng.sample(tokens, 1))},
        {'q': 140, 'revoked': sorted(qrng.sample(tokens, 3))}]
    queries = [{'entity': entities[0], 'attribute': attrs[0], 'contexts': contexts},
               {'entity': entities[-1], 'attribute': attrs[-1], 'contexts': deepcopy(contexts)}]
    return {'id': raw['cut'], 'regime': regime, 'seed': seed, 'stream': raw, 'queries': queries}

def scale_case(regime, size):
    p = policy(['entity-000'], ['service.label'], regime == 'private')
    events = []
    for i in range(size):
        parents = [f'node-{i-1:04d}'] if regime == 'chain' and i else []
        source = f's{i % 4}' if regime == 'chain' else 's0'
        events.append(node(f'node-{i:04d}', 'entity-000', 'service.label', source, 100, 100, 100, [i % 8] if regime != 'chain' else [1], parents))
    identity = f'scale-{regime}-{size}'
    raw = {'cut': identity, 'q0': 100, 'policy': p, 'events': events}
    revokes = [[], ['scope:0'], ['scope:1'], ['scope:2']]
    if regime == 'private':
        revokes = [[], ['scope:0'], ['n:node-0000'], [f'n:node-{size-1:04d}']]
    contexts = [{'q': q, 'revoked': r} for q, r in product((100, 150, 199, 200), revokes)]
    return {'id': identity, 'regime': regime, 'size': size, 'stream': raw,
            'queries': [{'entity': 'entity-000', 'attribute': 'service.label', 'contexts': contexts}]}

def stream_faults(intake):
    labels = ['missing-parent', 'derivation-cycle', 'wrong-derived-value', 'unauthorized-attribute',
              'unauthorized-alias', 'conflicting-replay', 'future-upper-time', 'reversed-interval',
              'zero-ttl', 'unknown-revocation', 'alias-cycle', 'duplicate-value', 'wrong-rule',
              'alias-as-parent', 'unknown-entity', 'unknown-top-field', 'boolean-time', 'time-overflow']
    for i, label in enumerate(labels):
        raw = deepcopy(intake); events = raw['events']
        root = next(x for x in events if x.get('id') == 'root')
        child = next(x for x in events if x.get('id') == 'copy')
        if i == 0: events.remove(root)
        elif i == 1: child['parents'] = ['copy']
        elif i == 2: child['value'] = [2]
        elif i == 3: raw['policy']['sources']['b']['attributes'] = []
        elif i == 4: raw['policy']['sources']['link']['alias'] = False
        elif i == 5:
            other = deepcopy(root); other['ttl'] += 1; events.append(other)
        elif i == 6: child['hi'] = raw['q0'] + 1
        elif i == 7: child['lo'], child['hi'] = 5, 4
        elif i == 8: root['ttl'] = 0
        elif i == 9: events.append({'kind': 'revoke', 'token': 'absent'})
        elif i == 10:
            edge = deepcopy(next(x for x in events if x.get('kind') == 'alias'))
            edge['id'] = 'other-bridge'; events.append(edge)
        elif i == 11: root['value'] = [1, 1]
        elif i == 12: root['rule'] = 'copy'
        elif i == 13: child['parents'] = ['bridge']
        elif i == 14: child['entity'] = 'entity-absent'
        elif i == 15: raw['unexpected'] = 1
        elif i == 16: root['lo'] = False
        elif i == 17: root['ttl'] = 2**31
        yield {'id': f'fault-{i:02d}', 'fault': label, 'stream': raw}

def valid_controls(intake):
    for i, label in enumerate(('permutation', 'observation-replay', 'alias-replay', 'known-revocation', 'irrelevant-revocation', 'new-cut')):
        raw = deepcopy(intake)
        if i == 0: random.Random(9).shuffle(raw['events'])
        elif i == 1: raw['events'].append(deepcopy(raw['events'][0]))
        elif i == 2: raw['events'].append(deepcopy(next(x for x in raw['events'] if x['kind'] == 'alias')))
        elif i == 3: raw['events'].extend([{'kind': 'revoke', 'token': 'a'}]*2)
        elif i == 4:
            raw['policy']['sources']['unused'] = {'priority': 0, 'attributes': ['tag'], 'alias': False, 'scopes': ['unused']}
            raw['events'].append({'kind': 'revoke', 'token': 'unused'})
        elif i == 5: raw['cut'] = 'different-valid-cut'
        yield {'id': f'control-{i:02d}', 'control': label, 'stream': raw}

def certificate_faults(cert):
    labels = ('cut', 'clock', 'deadline', 'missing-support', 'extra-support', 'missing-path', 'duplicate-path',
              'priority', 'rank-time', 'rank-identity', 'unknown-identity', 'duplicate-frontier',
              'missing-frontier', 'missing-cover', 'self-cover', 'false-dominator',
              'inactive-reason', 'missing-inactive', 'unknown-inactive', 'extra-field')
    for i, label in enumerate(labels):
        bad = deepcopy(cert)
        first = bad['frontier'][0]
        if i == 0: bad['cut'] = 'other-cut'
        elif i == 1: bad['q0'] += 1
        elif i == 2: first['deadline'] += 1
        elif i == 3: first['support'] = first['support'][1:]
        elif i == 4: first['support'].append('unknown')
        elif i == 5: first['path'] = []
        elif i == 6: first['path'] = ['bridge', 'bridge']
        elif i == 7: first['rank'][0] += 1
        elif i == 8: first['rank'][1] += 1
        elif i == 9: first['rank'][2] = 'other'
        elif i == 10: first['id'] = 'absent'
        elif i == 11: bad['frontier'].append(deepcopy(first))
        elif i == 12: bad['frontier'].pop()
        elif i == 13: bad['covered'] = []
        elif i == 14: bad['covered'][0]['by'] = bad['covered'][0]['id']
        elif i == 15: bad['covered'][0]['by'] = 'copy'
        elif i == 16: bad['inactive'][0]['reason'] = 'revoked'
        elif i == 17: bad['inactive'] = []
        elif i == 18: bad['inactive'][0]['id'] = 'missing'
        elif i == 19: bad['unused'] = 1
        if bad == cert:
            raise AssertionError('ineffective certificate mutation: ' + label)
        yield label, bad

def write_exact(path, rows):
    data = ''.join(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n' for row in rows)
    if path.exists() and path.read_text() != data:
        raise ValueError('refusing to overwrite a different frozen input: ' + str(path))
    path.write_text(data)

def generate(root):
    folder = Path(root) / 'inputs'; folder.mkdir(parents=True, exist_ok=True)
    intake = json.loads((folder / 'intake.json').read_text())
    write_exact(folder / 'abstract.jsonl', abstract_cases())
    write_exact(folder / 'traces.jsonl', (trace_case(i) for i in range(192)))
    write_exact(folder / 'scaling.jsonl', (scale_case(r, n) for r, n in product(('shared', 'private', 'chain'), (256, 512, 1024, 2000))))
    write_exact(folder / 'invalid-streams.jsonl', stream_faults(intake))
    write_exact(folder / 'valid-controls.jsonl', valid_controls(intake))
    return {'abstract': 768, 'traces': 192, 'scaling': 12, 'intake': 1, 'invalid_streams': 18, 'valid_controls': 6, 'total': 997}
