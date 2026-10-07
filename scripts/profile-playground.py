#!/usr/bin/env python3
"""Profile native SDK crypto and the Rust notary; never capture environment values."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--out", default=".zkf/profiles/local")
parser.add_argument("--seconds", type=int, default=20)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
out = (root / args.out).resolve()
out.mkdir(parents=True, exist_ok=True)
env = os.environ.copy()
env.update(ZKF_NOTARY_ADDR="127.0.0.1:0", PLAYGROUND_TLS_MATRIX="1",
           ZKF_STREAK_MINIMUM="365", PLAYGROUND_RESULTS=str(out / "measurements.json"),
           PLAYGROUND_PROFILE_DELAY_MS="3000")
children = []
files = []
try:
    notary_err = (out / "notary.log").open("w")
    files.append(notary_err)
    notary = subprocess.Popen([str(root / "target/release/zkf-notary")], cwd=root,
                              env=env, stdout=subprocess.PIPE, stderr=notary_err, text=True)
    children.append(notary)
    while True:
        line = notary.stdout.readline()
        if not line:
            raise RuntimeError("notary exited before readiness")
        if line.startswith("ZKF_NOTARY_READY "):
            _, addr, key = line.split()
            env.update(ZKF_NOTARY_URL=f"ws://{addr}", ZKF_NOTARY_PUBLIC_KEY=key)
            break
    output = (out / "playground.log").open("w")
    files.append(output)
    # Launch directly so the sampled PID is the native SDK process.
    client = subprocess.Popen([shutil.which("bun"), "packages/playground/src/duolingo.ts"],
                              cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT)
    children.append(client)
    for name, process in [("client", client), ("notary", notary)]:
        log = (out / f"sample-{name}.log").open("w")
        files.append(log)
        children.append(subprocess.Popen(["sample", str(process.pid), str(args.seconds), "1",
                                          "-file", str(out / f"sample-{name}.txt")],
                                         stdout=log, stderr=subprocess.STDOUT))
    trace_log = (out / "xctrace.log").open("w")
    files.append(trace_log)
    trace = subprocess.Popen(["xctrace", "record", "--template", "Time Profiler",
                              "--attach", str(client.pid), "--time-limit", f"{args.seconds}s",
                              "--output", str(out / "client.trace"), "--no-prompt"],
                             stdout=trace_log, stderr=subprocess.STDOUT)
    children.append(trace)
    code = client.wait(timeout=240)
    for profiler in children[-3:]:
        profiler.wait(timeout=args.seconds + 30)
    if code:
        raise RuntimeError(f"playground exited {code}; see {out / 'playground.log'}")
    print(f"Measurements, 1ms samples, and xctrace artifacts saved to {out}")
finally:
    for child in reversed(children):
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
    for file in files:
        file.close()
