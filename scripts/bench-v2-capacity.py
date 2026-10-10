#!/usr/bin/env python3
"""Synchronized 2/4/8/16-worker waves: cold then warm, separate native processes.

Use a dedicated notary with temporary admission quotas permitting the requested
levels. Never changes quotas itself. Reports failures rather than retrying HTTP.
Run the host metrics collector separately so local client CPU does not count as
instance CPU. Worker output and results contain no capabilities/session secrets.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--levels', default='2,4,8,16')
    parser.add_argument('--waves', type=int, default=3)
    parser.add_argument('--profile', choices=['ciphertext-only', 'signed-head'], default='ciphertext-only')
    parser.add_argument('--out', type=Path, default=Path('docs/benchmarks/d1-d5-completion/capacity.json'))
    args = parser.parse_args()
    if args.waves < 2 or args.waves > 100:
        parser.error('waves must be 2..100')
    levels = list(map(int, args.levels.split(',')))
    if any(level < 1 or level > 32 for level in levels):
        parser.error('levels must be 1..32')
    env = dict(os.environ, RAYON_NUM_THREADS='1', TOKIO_WORKER_THREADS='1',
               ZKF_CAPACITY_PROFILE=args.profile, ZKF_CAPACITY_WAVES=str(args.waves))
    report = {'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'complete': False,
              'profile': args.profile, 'waveCount': args.waves,
              'scope': 'native client processes; synchronized waves per level',
              'levels': [], 'waves': []}
    report['provenance'] = {
        path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
        for path in ['scripts/bench-v2-capacity.py', 'scripts/bench-v2-capacity-worker.ts',
                     'packages/native/zkf.node', '.zkf/aws/completion-artifacts/zkf-notary']
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    with tempfile.TemporaryDirectory(prefix='zkf-v2-capacity-') as directory:
        root = Path(directory)
        for level in levels:
            workers = []
            logs = []
            try:
                for worker in range(level):
                    log = (root / f'{level}-{worker}.log').open('w')
                    logs.append(log)
                    workers.append(subprocess.Popen(['bun', '--no-env-file', 'scripts/bench-v2-capacity-worker.ts',
                        directory, str(level), str(worker)], env=env, stdout=log, stderr=subprocess.STDOUT))
                deadline = time.monotonic() + 60
                while not all((root / f'{level}-{worker}.ready').exists() for worker in range(level)):
                    if time.monotonic() > deadline or any(p.poll() is not None for p in workers):
                        raise RuntimeError('capacity worker did not start')
                    time.sleep(.1)
                rows = []
                for wave in range(args.waves):
                    start = time.time()
                    (root / f'start-{level}-{wave}').touch()
                    deadline = time.monotonic() + 150
                    while not all((root / f'{level}-{worker}-{wave}.done').exists() for worker in range(level)):
                        if time.monotonic() > deadline:
                            raise RuntimeError(f'wave timed out: {level}/{wave}')
                        time.sleep(.1)
                    batch = [json.loads((root / f'{level}-{worker}-{wave}.done').read_text()) for worker in range(level)]
                    rows.extend(batch)
                    report['waves'].append({'level': level, 'wave': wave, 'start': start, 'end': time.time(), 'rows': batch})
                    args.out.write_text(json.dumps(report, indent=2) + '\n')
                    print(json.dumps({'level': level, 'wave': wave, 'verified': sum(r['ok'] for r in batch), 'attempted': level}), flush=True)
                    time.sleep(4)
                warm = [r['timings']['totalMs'] for r in rows if r['ok'] and r['round'] > 0]
                report['levels'].append({'parallel': level, 'verified': sum(r['ok'] for r in rows),
                    'attempted': len(rows), 'warmMedianMs': statistics.median(warm) if warm else None,
                    'resumedWarm': sum(r['ok'] and r['round'] > 0 and r['timings']['voleResumed'] for r in rows)})
                args.out.write_text(json.dumps(report, indent=2) + '\n')
            finally:
                for process in workers:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                for log in logs:
                    log.close()
            time.sleep(5)
    report['completedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['complete'] = True
    report['allVerified'] = all(level['verified'] == level['attempted'] for level in report['levels'])
    args.out.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
