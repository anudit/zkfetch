#!/usr/bin/env python3
"""Join capacity wave timestamps with independently collected EC2 samples."""
import argparse
import json
from pathlib import Path

KEEP = ['time', 'hostMemTotalKiB', 'hostMemAvailableKiB', 'swapUsedKiB',
        'diskUsed', 'diskTotal', 'hostCpuPct', 'iowaitPct', 'stealPct', 'restarts',
        'vmstat', 'memory.current', 'memory.peak', 'memory.swap.current',
        'memory.events', 'notaryMetrics']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capacity', type=Path, required=True)
    parser.add_argument('--metrics', type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.capacity.read_text())
    samples = [json.loads(line) for line in args.metrics.read_text().splitlines()]
    summary, selected = [], []
    for level in report['levels']:
        waves = [w for w in report['waves'] if w['level'] == level['parallel']]
        rows = [s for s in samples if any(w['start'] <= s['time'] <= w['end'] for w in waves)]
        if not rows:
            raise RuntimeError(f"No host samples for {level['parallel']} clients")
        selected.extend({k: row[k] for k in KEEP if k in row} for row in rows)
        summary.append({**level,
            'peakNotaryCgroupMiB': max(int(r.get('memory.current', '0') or '0') for r in rows) / 2**20,
            'minimumHostAvailableMiB': min(r['hostMemAvailableKiB'] for r in rows) / 1024,
            'peakHostCpuPct': max(r.get('hostCpuPct', 0) for r in rows),
            'peakSwapMiB': max(r['swapUsedKiB'] for r in rows) / 1024,
            'peakIowaitPct': max(r.get('iowaitPct', 0) for r in rows),
            'serviceRestarts': max(r['restarts'] for r in rows),
            'hostOomKillCounterStart': rows[0]['vmstat']['oom_kill'],
            'hostOomKillCounterEnd': rows[-1]['vmstat']['oom_kill'],
            'diskUsedGiB': max(r['diskUsed'] for r in rows) / 2**30})
    out = args.capacity.with_name(args.capacity.stem + '-summary.json')
    out.write_text(json.dumps({'complete': 'completedAt' in report,
        'allVerified': all(x['verified'] == x['attempted'] for x in summary),
        'scope': 'cgroup memory.current and host metrics sampled every 500 ms; peaks may be undersampled',
        'capacityReport': args.capacity.name, 'levels': summary}, indent=2) + '\n')
    args.capacity.with_name(args.capacity.stem + '-metrics.json').write_text(json.dumps(selected, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
