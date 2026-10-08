#!/usr/bin/env python3
"""Full QuickSilver sessions using separate, loopback-only notary/fixture processes.

Build first: cargo build --release -p zkf-notary -p zkf-fixture -p zkf-prover \
    --bins --example profile_quicksilver
Use --profiler samply for Rust stacks, or xctrace for an Instruments trace.
Outputs contain public fixture metadata and timings, never session secrets.
"""

import argparse
import base64
import os
from pathlib import Path
import selectors
import subprocess


def ready(process, prefix):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while selector.select(timeout=30):
            line = process.stdout.readline()
            if not line:
                raise RuntimeError(f"process exited before {prefix}")
            if line.startswith(prefix):
                return line.strip().split()[1:]
        raise TimeoutError(f"no {prefix} readiness message")
    finally:
        selector.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--mode", choices=["proxy", "mpc"], default="proxy")
    parser.add_argument("--tls", choices=["1.2", "1.3"], default="1.3")
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--profiler", choices=["none", "samply", "xctrace"], default="none")
    parser.add_argument("--binary-dir", type=Path, default=Path("target/release"))
    parser.add_argument("--rayon-threads", type=int)
    parser.add_argument("--max-sent", type=int)
    parser.add_argument("--max-recv", type=int)
    parser.add_argument("--no-predicates", action="store_true")
    args = parser.parse_args()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    binary_dir = args.binary_dir.resolve()
    env = os.environ.copy()
    env.update(ZKF_FIXTURE_ADDR="127.0.0.1:0", ZKF_FIXTURE_TLS_VERSION=args.tls,
               ZKF_NOTARY_ADDR="127.0.0.1:0", ZKF_NOTARY_KEY="07" * 32,
               RUST_LOG="error")
    env.pop("ZKF_HEALTH_ADDR", None)
    if args.rayon_threads:
        env["RAYON_NUM_THREADS"] = str(args.rayon_threads)
    children = []
    try:
        with (args.out / "fixture.log").open("w") as fixture_log, \
             (args.out / "notary.log").open("w") as notary_log, \
             (args.out / "client.log").open("w") as client_log:
            fixture = subprocess.Popen([str(binary_dir / "zkf-fixture")], env=env,
                                       stdout=subprocess.PIPE, stderr=fixture_log, text=True,
                                       bufsize=1)
            children.append(fixture)
            fixture_addr, domain, ca = ready(fixture, "ZKF_FIXTURE_READY")
            ca_path = args.out / "fixture-ca.der"
            ca_path.write_bytes(base64.b64decode(ca))
            env.update(ZKF_EXTRA_ROOTS=str(ca_path), ZKF_PROXY_RESOLVE=f"{domain}={fixture_addr}")
            notary = subprocess.Popen([str(binary_dir / "zkf-notary")], env=env,
                                      stdout=subprocess.PIPE, stderr=notary_log, text=True,
                                      bufsize=1)
            children.append(notary)
            notary_addr, key = ready(notary, "ZKF_NOTARY_READY")
            command = [str(binary_dir / "examples/profile_quicksilver"),
                       "--mode", args.mode, "--tls", args.tls,
                       "--runs", str(args.runs), "--warmup", str(args.warmup),
                       "--out", str(args.out / "measurements.json"),
                       "--notary-url", f"ws://{notary_addr}",
                       "--fixture-addr", fixture_addr, "--notary-key", key]
            for option in ["max_sent", "max_recv"]:
                value = getattr(args, option)
                if value is not None:
                    command += ["--" + option.replace("_", "-"), str(value)]
            if args.no_predicates:
                command += ["--no-predicates"]
            if args.profiler == "samply":
                command = ["samply", "record", "--save-only", "--rate", "1000",
                           "--profile-name", f"QuickSilver {args.mode} TLS {args.tls}",
                           "--output", str(args.out / "profile.json"), *command]
            elif args.profiler == "xctrace":
                command = ["xctrace", "record", "--template", "Time Profiler",
                           "--no-prompt", "--output", str(args.out / "client.trace"),
                           "--target-stdout", str(args.out / "target.log"),
                           "--launch", "--", *command]
            # CPU and memory accounting for the unprofiled client. The notary is separate.
            if args.profiler == "none":
                command = ["/usr/bin/time", "-l", *command]
            client = subprocess.Popen(command, env=env, stdout=client_log, stderr=client_log)
            children.append(client)
            client.wait(timeout=max(180, (args.runs + args.warmup) * 65))
            if client.returncode:
                raise RuntimeError(f"client failed: see {args.out / 'client.log'}")
            print(f"Completed: {args.out}", flush=True)
    finally:
        for process in reversed(children):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
