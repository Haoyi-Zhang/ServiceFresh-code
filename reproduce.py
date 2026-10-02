#!/usr/bin/env python3
"""Bounded, offline reproduction. Standard library; one sequential worker.

Examples:
  python reproduce.py --all --out results/reproduced --compare results/reference
  python reproduce.py --phase tiny --out results/reference
"""
import argparse
import csv
import json
import os
import platform
from pathlib import Path
import resource
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from copy import deepcopy
from itertools import product
from freshcert import cases
from freshcert.frontier import Candidate, frontier, query, transfer, budget_witness, budget_frontier
from freshcert.engine import Compiled, InvalidStream
from freshcert.checker import Prefix, check, AuditError, Verified

ROOT = Path(__file__).resolve().parent

class Counter:
    def __init__(self):
        self.checks = 0
    def test(self, condition, location):
        self.checks += 1
        if not condition:
            raise AssertionError(location)
        if self.checks > 85000:
            raise RuntimeError('per-phase obligation cap exceeded')

def bounded():
    affinity = {'supported': hasattr(os, 'sched_getaffinity'),
                'before': None, 'selected': None, 'after': None}
    if affinity['supported']:
        before = sorted(os.sched_getaffinity(0))
        selected = min(before)
        os.sched_setaffinity(0, {selected})
        affinity.update(before=before, selected=selected,
                        after=sorted(os.sched_getaffinity(0)))
    resource.setrlimit(resource.RLIMIT_AS, (2_500_000_000, 2_500_000_000))
    resource.setrlimit(resource.RLIMIT_CPU, (100, 100))
    return affinity

def runtime_environment(affinity):
    os_release = {}
    release_path = Path('/etc/os-release')
    if release_path.exists():
        for line in release_path.read_text(errors='replace').splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                os_release[key] = value.strip().strip('\"')
    cpu_model = None
    cpuinfo = Path('/proc/cpuinfo')
    if cpuinfo.exists():
        for line in cpuinfo.read_text(errors='replace').splitlines():
            if ':' in line and line.split(':', 1)[0].strip() in {'model name', 'Processor', 'Hardware'}:
                cpu_model = line.split(':', 1)[1].strip()
                if cpu_model:
                    break
    return {
        'recorded_at_utc': datetime.now(timezone.utc).isoformat(),
        'python': {
            'implementation': platform.python_implementation(),
            'version': platform.python_version(),
            'full_version': sys.version.replace('\n', ' '),
            'executable': sys.executable,
        },
        'cpu': {
            'architecture': platform.machine(),
            'model': cpu_model or 'not exposed to process',
            'logical_count_visible_before_affinity': (len(affinity['before'])
                                                       if affinity['before'] is not None else None),
        },
        'os': {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'distribution': os_release.get('PRETTY_NAME', 'not recorded'),
            'execution_image': 'not exposed to process',
        },
        'affinity': affinity,
    }

def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def rows(name):
    with (ROOT / 'inputs' / name).open() as f:
        return [json.loads(line) for line in f if line.strip()]

def csv_write(path, records):
    records = list(records)
    if not records:
        raise ValueError('empty result table: ' + str(path))
    with path.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(records[0]))
        w.writeheader(); w.writerows(records)

def brute(A, q, r):
    # Raw triples; deliberately does not call frontier, dominance, or budget code.
    alive = [(i, d, s) for i, d, s in A if d > q and (s & r) == 0]
    return max((i for i, _, _ in alive), default=None)

def tiny(out, counter):
    results = []; contexts = 0; bounded_contexts = 0
    for case in rows('abstract.jsonl'):
        name = case['id']; m = case['tokens']; n = len(case['deadlines'])
        raw = [(i, case['deadlines'][i], case['supports'][i]) for i in range(n)]
        A = tuple(Candidate(str(i), (0, 0, str(i)), d, s) for i, d, s in raw)
        F = frontier(A); keep = {int(x.identity) for x in F}
        possible = [set() for _ in range(m+1)]
        context_results = []
        for q, R in product(range(4), range(1 << m)):
            expected = brute(raw, q, R)
            actual = query(F, q, R)
            counter.test(actual == (None if expected is None else str(expected)), name + ': winner')
            live_all = tuple(x for x in A if q < x.deadline and not x.support & R)
            live_frontier = tuple(x for x in F if q < x.deadline and not x.support & R)
            counter.test(frontier(live_all) == live_frontier, name + ': filter commutation')
            for b in range(R.bit_count(), m+1):
                if expected is not None:
                    possible[b].add(expected)
            context_results.append((q, R, expected)); contexts += 1
        for i, _, _ in raw:
            counter.test((i in keep) == (i in possible[m]), name + ': unrestricted necessity')
        budget_sizes = []
        for b in range(m+1):
            B = budget_frontier(A, b); budget_sizes.append(len(B))
            for x in A:
                witness = budget_witness(x, A, b)
                expected = int(x.identity) in possible[b]
                valid = witness is None or (witness.bit_count() <= b and brute(raw, x.deadline-1, witness) == int(x.identity))
                counter.test((witness is not None) == expected and valid, name + ': bounded witness')
            if b == 1:
                for q, R, expected in context_results:
                    if R.bit_count() <= 1:
                        counter.test(query(B, q, R) == (None if expected is None else str(expected)), name + ': budget-one query')
                        bounded_contexts += 1
        for mask in range(1 << n):
            left = tuple(x for i, x in enumerate(A) if mask >> i & 1)
            right = tuple(x for i, x in enumerate(A) if not mask >> i & 1)
            counter.test(frontier(frontier(left) + frontier(right)) == F, name + ': compatible merge')
        for deadline, support in product((1, 3), (0, (1 << m)-1)):
            counter.test(frontier(transfer(F, deadline, support)) == frontier(transfer(A, deadline, support)), name + ': transfer')
        counter.test(frontier(reversed(A)) == F, name + ': order')
        results.append({'case': name, 'candidates': n, 'tokens': m, 'frontier': len(F),
                        'budget0': budget_sizes[0], 'budget1': budget_sizes[1], 'budget_unrestricted': budget_sizes[-1],
                        'contexts': 4*(1 << m)})
    csv_write(out/'tiny-cases.csv', results)
    return {'cases': len(results), 'contexts': contexts, 'budget_one_contexts': bounded_contexts,
            'retained_candidates': sum(x['frontier'] for x in results)}

def weak_candidates(compiled, entity, attr):
    # Static reachability is kept for the ablations; edge liveness is deliberately
    # omitted only in the named no-alias/timestamp-only variants.
    route = {entity: ()}; todo = [entity]
    while todo:
        here = todo.pop()
        for there, edge in compiled.adj[here]:
            if there not in route:
                route[there] = route[here] + (edge,); todo.append(there)
    variants = {k: [] for k in ('timestamp-only', 'no-ancestor-expiry', 'no-ancestor-revocation', 'no-alias-obligations')}
    for key, row in compiled.nodes.items():
        if row['attribute'] != attr or row['entity'] not in route:
            continue
        path = route[row['entity']]
        pd, ps = 2**32-1, 0
        for edge in path:
            pd = min(pd, compiled.deadline[edge]); ps |= compiled.support[edge]
        local_s = compiled.mask(compiled.policy['sources'][row['source']]['scopes'])
        if compiled.policy['node_scopes']:
            local_s |= 1 << compiled.index['n:' + key]
        local_d = row['lo'] + row['ttl']
        rank = (compiled.policy['sources'][row['source']]['priority'], row['lo'], key)
        variants['timestamp-only'].append(Candidate(key, rank, local_d, local_s))
        variants['no-ancestor-expiry'].append(Candidate(key, rank, min(pd, local_d), ps | compiled.support[key]))
        variants['no-ancestor-revocation'].append(Candidate(key, rank, min(pd, compiled.deadline[key]), ps | local_s))
        variants['no-alias-obligations'].append(Candidate(key, rank, compiled.deadline[key], compiled.support[key]))
    return variants

def trace_batch(out, counter, batch):
    cases_in_batch = rows('traces.jsonl')[32*batch:32*(batch+1)]
    summaries, answers = [], []
    for case in cases_in_batch:
        raw = case['stream']; started = time.perf_counter_ns(); c = Compiled(raw)
        producer_parse_us = (time.perf_counter_ns()-started)/1000
        started = time.perf_counter_ns(); p = Prefix(raw)
        checker_parse_us = (time.perf_counter_ns()-started)/1000
        reverse = deepcopy(raw); reverse['events'].reverse(); reversed_c = Compiled(reverse)
        replay = deepcopy(raw)
        replay['events'].append(deepcopy(next(x for x in raw['events'] if x['kind'] != 'revoke')))
        replay_c = Compiled(replay)
        for qi, spec in enumerate(case['queries']):
            entity, attr = spec['entity'], spec['attribute']
            started = time.perf_counter_ns(); cert = c.certificate(entity, attr)
            build_us = (time.perf_counter_ns()-started)/1000
            started = time.perf_counter_ns(); verified = check(p, cert, expected_entity=entity, expected_attribute=attr)
            check_us = (time.perf_counter_ns()-started)/1000
            all_compiled, _ = c.summaries(entity, attr)
            counter.test(reversed_c.certificate(entity, attr) == cert, case['id'] + ': event permutation')
            counter.test(replay_c.certificate(entity, attr) == cert, case['id'] + ': exact replay')
            variants = weak_candidates(c, entity, attr)
            variants['top-one'] = sorted(all_compiled, key=lambda x:x.rank, reverse=True)[:1]
            # Deliberately remove support inclusion from the pruning relation, not
            # from future liveness. This isolates a retention-policy ablation.
            variants['expiry-skyline'] = [x for x in all_compiled if not any(y.rank > x.rank and y.deadline >= x.deadline for y in all_compiled)]
            summaries.append({'case': case['id'], 'regime': case['regime'], 'query': qi,
                'records': len(c.nodes)+len(c.aliases), 'events': len(raw['events']), 'eligible': len(all_compiled),
                'frontier': len(cert['frontier']), 'bootstrap_bytes': len(json.dumps(cert, sort_keys=True, separators=(',', ':')).encode()),
                'frontier_entry_bytes': len(json.dumps(cert['frontier'], sort_keys=True, separators=(',', ':')).encode()),
                'producer_parse_us': producer_parse_us, 'checker_parse_us': checker_parse_us,
                'certificate_us': build_us, 'check_us': check_us})
            for ci, context in enumerate(spec['contexts']):
                q, revoked = context['q'], context['revoked']
                expected, eligible = p.direct(entity, attr, q, revoked, details=True)
                actual = verified.query(q, revoked, current_cut=raw['cut'])
                full = query(all_compiled, q, c.mask(revoked)|c.known)
                counter.test(actual == expected, case['id'] + ': verified cache')
                counter.test(full == expected, case['id'] + ': full compiled')
                predictions = {'direct': expected, 'verified': actual, 'full-compiled': full}
                predictions.update({name: query(pool, q, c.mask(revoked)|c.known) for name, pool in variants.items()})
                expected_value = None if expected is None else tuple(p.nodes[expected]['value'])
                for method, predicted in predictions.items():
                    value = None if predicted is None else tuple(p.nodes[predicted]['value'])
                    answers.append({'case': case['id'], 'regime': case['regime'], 'query': qi, 'context': ci,
                        'method': method, 'expected': expected or '', 'returned': predicted or '',
                        'id_error': int(predicted != expected), 'value_error': int(value != expected_value),
                        'unsafe_return': int(predicted is not None and predicted not in eligible)})
    csv_write(out/f'traces-{batch:02d}.csv', summaries)
    csv_write(out/f'traces-{batch:02d}-queries.csv', answers)
    return {'cases': len(cases_in_batch), 'queries': len(summaries), 'contexts': len(cases_in_batch)*24}

def scaling(out, counter, index):
    case = rows('scaling.jsonl')[index]; raw = case['stream']; spec = case['queries'][0]
    entity, attr = spec['entity'], spec['attribute']
    start = time.perf_counter_ns(); c = Compiled(raw); cert = c.certificate(entity, attr)
    producer_us = (time.perf_counter_ns()-start)/1000
    start = time.perf_counter_ns(); p = Prefix(raw); verified = check(p, cert, expected_entity=entity, expected_attribute=attr)
    checker_us = (time.perf_counter_ns()-start)/1000
    start = time.perf_counter_ns(); full_prefix = Prefix(raw)
    full_summaries, _ = full_prefix.summaries(entity, attr)
    full_sets = Verified(full_prefix.cut, full_prefix.q0, entity, attr, full_prefix.tokens, tuple(full_summaries.values()))
    full_set_setup_us = (time.perf_counter_ns()-start)/1000
    all_compiled, _ = c.summaries(entity, attr)
    contexts = [(x['q'], x['revoked'], c.mask(x['revoked'])|c.known) for x in spec['contexts']]
    expected = [p.direct(entity, attr, q, r) for q, r, m in contexts]
    actual = [verified.query(q, r, current_cut=raw['cut']) for q, r, m in contexts]
    full = [query(all_compiled, q, m) for q, r, m in contexts]
    full_set_results = [full_sets.query(q,r,current_cut=raw['cut']) for q,r,m in contexts]
    for i in range(len(expected)):
        counter.test(expected[i] == actual[i], case['id'] + ': cache')
        counter.test(expected[i] == full[i], case['id'] + ': compiled')
        counter.test(expected[i] == full_set_results[i], case['id'] + ': matched full set cache')
    functions = {'direct': lambda q,r,m: p.direct(entity,attr,q,r),
                 'full-compiled': lambda q,r,m: query(all_compiled,q,m),
                 'verified': lambda q,r,m: verified.query(q,r,current_cut=raw['cut']),
                 'full-set-cache': lambda q,r,m: full_sets.query(q,r,current_cut=raw['cut'])}
    timing = []
    methods = list(functions)
    for batch in range(5):
        order = methods[batch % len(methods):] + methods[:batch % len(methods)]
        for method in order:
            fn = functions[method]
            cpu = time.process_time_ns(); wall = time.perf_counter_ns()
            for repetition in range(8):
                observed = [fn(q, r, m) for q, r, m in contexts]
            wall = time.perf_counter_ns()-wall; cpu = time.process_time_ns()-cpu
            counter.test(observed == expected, case['id'] + ': timing output')
            timing.append({'case': case['id'], 'regime': case['regime'], 'records': case['size'],
                           'method': method, 'batch': batch, 'query_calls': 128,
                           'wall_ns': wall, 'cpu_ns': cpu, 'wall_us_per_query': wall/128000})
    csv_write(out/f'scale-{index:02d}-timing.csv', timing)
    csv_write(out/f'scale-{index:02d}-queries.csv', ({'context':i,'expected':expected[i] or '', 'verified':actual[i] or '', 'full_compiled':full[i] or '', 'full_set_cache':full_set_results[i] or ''} for i in range(16)))
    dump(out/f'scale-{index:02d}-case.json', {'case':case['id'], 'regime':case['regime'], 'records':case['size'],
        'eligible':len(all_compiled),'frontier':len(cert['frontier']), 'producer_us':producer_us,'checker_us':checker_us, 'full_set_setup_us':full_set_setup_us,
        'bootstrap_bytes':len(json.dumps(cert,sort_keys=True,separators=(',',':')).encode()),
        'frontier_entry_bytes':len(json.dumps(cert['frontier'],sort_keys=True,separators=(',',':')).encode())})
    return {'cases':1, 'contexts':16, 'timed_query_calls':len(timing)*128}

def faults(out, counter):
    records = []; intake = json.loads((ROOT/'inputs/intake.json').read_text())
    c = Compiled(intake); cert = c.certificate('e0','tag'); p = Prefix(intake); verified = check(p, cert, expected_entity='e0', expected_attribute='tag')
    for q, mask in product(range(5,32), range(8)):
        revoked = [x for i,x in enumerate(('a','b','link')) if mask>>i&1]
        counter.test(p.direct('e0','tag',q,revoked) == verified.query(q,revoked,current_cut=intake['cut']), 'retained intake query')
    for case in rows('invalid-streams.jsonl'):
        for method, fn, error in (('producer', Compiled, InvalidStream), ('checker', Prefix, AuditError)):
            try: fn(case['stream'])
            except error as exc: rejected, reason = True, str(exc)
            else: rejected, reason = False, 'accepted'
            counter.test(rejected, case['id'] + ':' + method)
            records.append({'case':case['id'], 'kind':'invalid-stream', 'fault':case['fault'], 'method':method, 'rejected':int(rejected), 'reason':reason})
    for case in rows('valid-controls.jsonl'):
        raw = case['stream']; producer = Compiled(raw); independent = Prefix(raw)
        accepted = check(independent, producer.certificate('e0','tag'), expected_entity='e0', expected_attribute='tag')
        for q, mask in product(range(5,32), range(8)):
            revoked = [x for i,x in enumerate(('a','b','link')) if mask>>i&1]
            counter.test(independent.direct('e0','tag',q,revoked) == accepted.query(q,revoked,current_cut=raw['cut']), case['id'] + ': valid control')
        records.append({'case':case['id'], 'kind':'valid-control', 'fault':case['control'], 'method':'both', 'rejected':0, 'reason':'accepted and replay-equivalent'})
    mutations = []
    for i,(label,bad) in enumerate(cases.certificate_faults(cert)):
        try: check(p, bad, expected_entity='e0', expected_attribute='tag')
        except AuditError as exc: rejected, reason = True, str(exc)
        else: rejected, reason = False, 'accepted'
        counter.test(rejected, 'certificate fault:' + label)
        records.append({'case':f'certificate-{i:02d}', 'kind':'certificate', 'fault':label, 'method':'checker', 'rejected':int(rejected),'reason':reason})
        mutations.append({'case':f'certificate-{i:02d}', 'fault':label, 'certificate':bad})
    guard_inputs = [('cut',6,[], 'unrelated-cut'),('past-time',4,[],intake['cut']),
                    ('unknown-scope',6,['missing'],intake['cut']),('boolean-time',True,[],intake['cut'])]
    for label,q,r,cut in guard_inputs:
        try: verified.query(q,r,current_cut=cut)
        except AuditError as exc: rejected, reason = True, str(exc)
        else: rejected, reason = False, 'accepted'
        counter.test(rejected, 'cache guard:' + label)
        records.append({'case':'guard-'+label,'kind':'cache-guard','fault':label,'method':'checker','rejected':int(rejected),'reason':reason})
    (out/'certificate-mutations.jsonl').write_text(''.join(json.dumps(x,sort_keys=True)+'\n' for x in mutations))
    csv_write(out/'faults.csv', records); dump(out/'intake-certificate.json',cert)
    return {'cases':25, 'invalid_streams':18, 'invalid_stream_rejections':36, 'valid_controls':6,
            'certificate_mutations':20,'cache_guard_faults':4, 'intake_contexts':216, 'valid_control_contexts':1296}

def phase_name(phase, index):
    return f'{phase}-{index:02d}' if phase in {'traces','scale'} else phase

def run_phase(phase, index, out):
    affinity = bounded(); environment = runtime_environment(affinity)
    counter = Counter(); cpu = time.process_time_ns(); wall = time.perf_counter_ns()
    functions = {'inputs':lambda:cases.generate(ROOT), 'tiny':lambda:tiny(out,counter),
                 'traces':lambda:trace_batch(out,counter,index), 'scale':lambda:scaling(out,counter,index),
                 'faults':lambda:faults(out,counter)}
    result = functions[phase]()
    result.update({'phase':phase_name(phase,index), 'checks':counter.checks, 'cpu_seconds':(time.process_time_ns()-cpu)/1e9,
                   'wall_seconds':(time.perf_counter_ns()-wall)/1e9,
                   'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'worker_count':1,
                   'environment':environment,'status':'passed'})
    dump(out/(phase_name(phase,index)+'-run.json'),result)
    print(json.dumps(result,sort_keys=True),flush=True)

def summary(out):
    needed=['inputs','tiny', *[f'traces-{i:02d}' for i in range(6)], *[f'scale-{i:02d}' for i in range(12)], 'faults']
    runs=[json.loads((out/(name+'-run.json')).read_text()) for name in needed]
    checks=sum(x['checks'] for x in runs)
    if checks>85000: raise RuntimeError('whole-campaign obligation cap exceeded')
    methods={}
    for file in sorted(out.glob('traces-*-queries.csv')):
        for row in csv.DictReader(file.open()):
            key=row['method']; z=methods.setdefault(key,{'contexts':0,'id_errors':0,'value_errors':0,'unsafe_returns':0})
            z['contexts']+=1; z['id_errors']+=int(row['id_error']); z['value_errors']+=int(row['value_error']); z['unsafe_returns']+=int(row['unsafe_return'])
    semantics={'campaign_entries':997,'abstract_models':768,'full_event_stream_cases':229,'checks':checks,
               'tiny_contexts':21504,'trace_contexts':4608,'scaling_contexts':192,'methods':methods,
               'invalid_streams_rejected_by_each':18,'valid_controls_accepted':6,'certificate_faults_rejected':20,'cache_guard_faults_rejected':4}
    dump(out/'semantic-summary.json',semantics)
    runtime={'runs':len(runs),'cpu_seconds':sum(x['cpu_seconds'] for x in runs),'wall_seconds':sum(x['wall_seconds'] for x in runs),
             'peak_rss_kib':max(x['peak_rss_kib'] for x in runs),'checks':checks,'workers':1,'phase_limits':{'cpu_seconds':100,'wall_seconds':120,'address_space_bytes':2500000000},
             'environment_file':'environment.json'}
    dump(out/'runtime-summary.json',runtime)
    phase_environments=[x.get('environment') for x in runs]
    if not all(phase_environments):
        raise RuntimeError('phase environment metadata missing')
    stable_keys=('python','cpu','os')
    baseline={key:phase_environments[0][key] for key in stable_keys}
    if any(any(env[key] != baseline[key] for key in stable_keys) for env in phase_environments[1:]):
        raise RuntimeError('phase environment metadata changed within one run')
    affinity_records=[env['affinity'] for env in phase_environments]
    if any(a.get('supported') and a.get('after') != [a.get('selected')] for a in affinity_records):
        raise RuntimeError('one-core affinity was not established')
    environment={**baseline, 'affinity_policy':'one logical CPU per phase, selected as the minimum CPU in the inherited allowed mask',
                 'phase_affinity':affinity_records, 'phase_count':len(runs),
                 'first_recorded_at_utc':phase_environments[0]['recorded_at_utc'],
                 'last_recorded_at_utc':phase_environments[-1]['recorded_at_utc'],
                 'scope':'this execution only; not evidence for a different retained run'}
    dump(out/'environment.json',environment)
    scale_rows=[]
    for i in range(12):
        row=json.loads((out/f'scale-{i:02d}-case.json').read_text())
        timing=list(csv.DictReader((out/f'scale-{i:02d}-timing.csv').open()))
        for method in ('direct','full-compiled','verified','full-set-cache'):
            values=[float(x['wall_us_per_query']) for x in timing if x['method']==method]
            row[method+'_median_us']=statistics.median(values);row[method+'_min_us']=min(values);row[method+'_max_us']=max(values)
        scale_rows.append(row)
    csv_write(out/'scaling-summary.csv',scale_rows)
    print(json.dumps({'semantic_summary':semantics,'runtime_summary':runtime},sort_keys=True),flush=True)
    return semantics

def compare(actual, expected):
    files=['semantic-summary.json','tiny-cases.csv','faults.csv','certificate-mutations.jsonl','intake-certificate.json']
    files += [f'traces-{i:02d}-queries.csv' for i in range(6)]
    files += [f'scale-{i:02d}-queries.csv' for i in range(12)]
    for name in files:
        if (actual/name).read_bytes() != (expected/name).read_bytes():
            raise AssertionError('discrete reproduction differs: '+name)
    for i in range(6):
        def stable(folder):
            return [{k:v for k,v in r.items() if not k.endswith('_us')} for r in csv.DictReader((folder/f'traces-{i:02d}.csv').open())]
        if stable(actual)!=stable(expected): raise AssertionError('trace case statistics differ')
    for i in range(12):
        def stable(folder):
            return {k:v for k,v in json.loads((folder/f'scale-{i:02d}-case.json').read_text()).items() if not k.endswith('_us')}
        if stable(actual)!=stable(expected): raise AssertionError('scaling case statistics differ')
    result={'status':'passed','exact_discrete_files':len(files),'exact_case_tables':18,
            'timing_equality_required':False,'interpretation':'Independent execution of the same supplied code and inputs; not an independent scientific review.'}
    dump(actual/'comparison.json',result);return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=['inputs','tiny','traces','scale','faults','summary'])
    parser.add_argument('--index',type=int,default=0)
    parser.add_argument('--all',action='store_true')
    parser.add_argument('--out',type=Path,default=ROOT/'results/reproduced')
    parser.add_argument('--compare',type=Path)
    args=parser.parse_args();out=args.out.resolve();out.mkdir(parents=True,exist_ok=True)
    if args.all:
        sequence=[('inputs',0),('tiny',0), *[('traces',i) for i in range(6)], *[('scale',i) for i in range(12)], ('faults',0)]
        for phase,index in sequence:
            subprocess.run([sys.executable,str(Path(__file__).resolve()),'--phase',phase,'--index',str(index),'--out',str(out)],check=True,timeout=120,cwd=ROOT)
        summary(out)
    elif args.phase=='summary': summary(out)
    elif args.phase:
        if args.phase=='traces' and not 0<=args.index<6: parser.error('trace index must be in [0,5]')
        if args.phase=='scale' and not 0<=args.index<12: parser.error('scale index must be in [0,11]')
        run_phase(args.phase,args.index,out)
    else: parser.error('use --all or --phase')
    if args.compare:
        print(json.dumps(compare(out,args.compare.resolve()),sort_keys=True))

if __name__=='__main__':
    main()
