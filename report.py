#!/usr/bin/env python3
"""Derive manuscript tables/plot data from retained raw results; offline stdlib."""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from statistics import median


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, data: list[dict]) -> None:
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(data[0]))
        w.writeheader()
        w.writerows(data)


def generate(source: Path, out: Path) -> None:
    summary = json.loads((source/'semantic-summary.json').read_text())
    answers = [r for i in range(6) for r in rows(source/f'traces-{i:02d}-queries.csv')]
    totals = {}
    for row in answers:
        item = totals.setdefault(row['method'], dict(contexts=0, id_errors=0,
                                                      value_errors=0, unsafe_returns=0))
        item['contexts'] += 1
        for a, b in [('id_error', 'id_errors'), ('value_error', 'value_errors'),
                     ('unsafe_return', 'unsafe_returns')]:
            item[b] += int(row[a])
    if totals != summary['methods']:
        raise ValueError('raw trace answers disagree with semantic summary')
    out.mkdir(parents=True, exist_ok=True)
    methods = [('direct', 'Direct replay'), ('full-compiled', 'Full compiled'),
               ('verified', 'Verified frontier'), ('expiry-skyline', 'Expiry skyline'),
               ('top-one', 'Top-one'), ('timestamp-only', 'Timestamp only'),
               ('no-ancestor-expiry', 'No ancestor expiry'),
               ('no-ancestor-revocation', 'No ancestor revocation'),
               ('no-alias-obligations', 'No alias obligations')]
    write_csv(out/'method-errors.csv', [{'method': k, **totals[k]} for k, _ in methods])
    tex = ['\\begin{tabular}{lrrr}', '\\toprule',
           'Method & ID errors & Value errors & Invalid returns\\\\', '\\midrule']
    for k, label in methods:
        z = totals[k]
        tex.append(f"{label} & {z['id_errors']:,} & {z['value_errors']:,} & {z['unsafe_returns']:,}\\\\")
    tex += ['\\bottomrule', '\\end{tabular}']
    (out/'method-errors.tex').write_text('\n'.join(tex)+'\n')

    traces = [r for i in range(6) for r in rows(source/f'traces-{i:02d}.csv')]
    regimes = ['mixed', 'and-dependency', 'alias-chain', 'replay-order',
               'clock-interval', 'private-scopes']
    labels = ['Mixed', 'AND dependency', 'Alias chain', 'Replay/order',
              'Clock intervals', 'Private scopes']
    aggregation = []
    for regime in regimes:
        group = [r for r in traces if r['regime'] == regime]
        ratios = [int(r['frontier'])/int(r['eligible']) for r in group if int(r['eligible'])]
        aggregation.append(dict(regime=regime, queries=len(group),
            eligible=sum(int(r['eligible']) for r in group),
            frontier=sum(int(r['frontier']) for r in group),
            median_ratio=median(ratios),
            median_bootstrap_bytes=median(int(r['bootstrap_bytes']) for r in group),
            median_check_us=median(float(r['check_us']) for r in group)))
    write_csv(out/'regimes.csv', aggregation)
    tex = ['\\begin{tabular}{lrrr}', '\\toprule',
           'Regime & Eligible & Retained & Median $F/M$\\\\', '\\midrule']
    for z, label in zip(aggregation, labels):
        tex.append(f"{label} & {z['eligible']:,} & {z['frontier']:,} & {z['median_ratio']:.3f}\\\\")
    tex += ['\\bottomrule', '\\end{tabular}']
    (out/'regimes.tex').write_text('\n'.join(tex)+'\n')

    scale = rows(source/'scaling-summary.csv')
    # Reconcile summary medians with every raw batch, not an independently typed table.
    for i, row in enumerate(scale):
        timing = rows(source/f'scale-{i:02d}-timing.csv')
        for method in ['direct', 'full-compiled', 'verified', 'full-set-cache']:
            values = [float(x['wall_us_per_query']) for x in timing if x['method'] == method]
            if len(values) != 5 or median(values) != float(row[method+'_median_us']):
                raise ValueError('raw timing disagrees with scale summary')
    scale_data = []
    for z in scale:
        scale_data.append(dict(regime=z['regime'], records=int(z['records']),
            frontier=int(z['frontier']), bootstrap_bytes=int(z['bootstrap_bytes']),
            summary_bytes=int(z['frontier_entry_bytes']),
            producer_ms=float(z['producer_us'])/1000,
            checker_ms=float(z['checker_us'])/1000,
            full_setup_ms=float(z['full_set_setup_us'])/1000,
            full_us=float(z['full-set-cache_median_us']),
            verified_us=float(z['verified_median_us']),
            full_min_us=float(z['full-set-cache_min_us']),
            full_max_us=float(z['full-set-cache_max_us']),
            verified_min_us=float(z['verified_min_us']),
            verified_max_us=float(z['verified_max_us'])))
    write_csv(out/'scaling.csv', scale_data)
    for regime in ['shared', 'private', 'chain']:
        write_csv(out/f'{regime}.csv', [z for z in scale_data if z['regime'] == regime])
    tex = ['\\begin{tabular}{lrrrrrr}', '\\toprule',
           'Policy / records & $F$ & Build & Check & Full setup & Full query & Frontier query\\\\',
           ' & & ms & ms & ms & $\\mu$s & $\\mu$s\\\\', '\\midrule']
    for z in scale_data:
        tex.append(f"{z['regime'].capitalize()} / {z['records']:,} & {z['frontier']:,} & {z['producer_ms']:.2f} & {z['checker_ms']:.2f} & {z['full_setup_ms']:.2f} & {z['full_us']:.2f} & {z['verified_us']:.2f}\\\\")
    tex += ['\\bottomrule', '\\end{tabular}']
    (out/'scaling.tex').write_text('\n'.join(tex)+'\n')
    print(json.dumps(dict(status='passed', trace_rows=len(answers),
          trace_queries=len(traces), scale_cases=len(scale_data),
          eligible=sum(z['eligible'] for z in aggregation),
          retained=sum(z['frontier'] for z in aggregation)), sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, default=Path('results/reference'))
    parser.add_argument('--out', type=Path, default=Path('results/paper-data'))
    args = parser.parse_args()
    generate(args.results, args.out)
