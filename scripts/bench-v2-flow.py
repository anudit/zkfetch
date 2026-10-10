#!/usr/bin/env python3
"""D4-1 fixture matrix: v1 FLOW3 and three v2 profiles at 0/33/100 ms RTT.

Build first: cargo build --locked --release -p zkf-prover --example profile_quicksilver
Each case has a fresh in-process notary, one cold warmup and four warm samples.
TCP read boundaries are observations; separate WebSocket metadata checks the
final client proof flight without exporting payloads.
"""
import argparse
import datetime
import hashlib
import json
import os
import platform
from pathlib import Path
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("docs/benchmarks/d1-d5-completion"))
    parser.add_argument("--runs", type=int, default=4)
    parser.add_argument("--binary", type=Path, default=Path("target/release/examples/profile_quicksilver"))
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    args.out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, RUST_LOG="error")
    cases = {"v1": [], "ciphertext-only": ["--attestation-v2"],
             "signed-head": ["--attestation-v2", "--signed-head"],
             "session-claim": ["--attestation-v2", "--session-claim"]}
    summary = {"scope": "local native synthetic fixture, not hosted or Chrome", "cases": [],
               "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "sourceRevision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
               "machine": {"system": platform.system(), "architecture": platform.machine(), "logicalCpus": os.cpu_count()},
               "sourceDigests": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in
                                 [Path("crates/zkf-prover/examples/profile_quicksilver.rs"),
                                  Path("crates/zkf-prover/examples/profile_quicksilver/relay.rs"),
                                  Path("crates/zkf-ir/src/backend/mpz.rs"),
                                  Path("crates/zkf-ir/src/response.rs"),
                                  Path("vendor/tlsn-mux/src/connection/active.rs"),
                                  Path(__file__)]}}
    summary["binarySha256"] = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    summary["workingTreeDirty"] = bool(subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], text=True).strip())
    for profile, flags in cases.items():
        for rtt in [0, 33, 100]:
            path = args.out / f"{profile}-{rtt}ms.json"
            command = [str(args.binary.resolve()), "--runs", str(args.runs), "--warmup", "1",
                       "--rtt-ms", str(rtt), "--out", str(path), *flags]
            with (args.out / f"{profile}-{rtt}ms.log").open("w") as log:
                subprocess.run(command, env=env, stdout=log, stderr=log, check=True,
                               timeout=(args.runs + 1) * 65)
            data = json.loads(path.read_text())
            warm = [r for r in data["runs"] if not r["warmup"]]
            assert len(warm) == args.runs and all(r["verified"] for r in warm)
            assert all(r["timings"]["voleResumed"] for r in warm), "warm pool not resumed"
            proof_counts = []
            trailing_counts = []
            for run in warm:
                frames = sorted(run["webSocketFrames"], key=lambda f: (f["connection"], f["micros"]))
                last_up = max(i for i, f in enumerate(frames) if f["direction"] == "up" and f["opcode"] in [0, 2])
                preceding_down = max(i for i in range(last_up) if frames[i]["direction"] == "down")
                proof = [f for f in frames[preceding_down + 1:last_up + 1] if f["direction"] == "up" and f["opcode"] in [0, 2]]
                # Mux shutdown/control frames can follow the single large
                # proof write. Report them separately, rather than hiding them
                # or treating TCP reads as application writes.
                large = [f for f in proof if f["payload_bytes"] > 64]
                assert len(large) == 1 and large[0]["fin"] and large[0]["opcode"] == 2, "proof flight is fragmented"
                proof_counts.append(len(large))
                trailing_counts.append(len(proof) - len(large))
            row = {"proofFlightBinaryMessages": proof_counts,
                   "smallControlMessagesInFinalFlight": trailing_counts,
                   "profile": profile, "rttMs": rtt, "verified": len(warm),
                   "medianTimings": {k: statistics.median(r["timings"][k] for r in warm)
                                     for k, v in warm[0]["timings"].items()
                                     if isinstance(v, (int, float)) and not isinstance(v, bool)},
                   "medianTrafficUpDownChanges": [statistics.median(r["trafficUpDownChanges"][i] for r in warm) for i in range(3)],
                   "medianPresentMs": statistics.median(r["presentMs"] for r in warm),
                   "medianVerifyMs": statistics.median(r["verifyMs"] for r in warm)}
            summary["cases"].append(row)
            (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            print(json.dumps(row), flush=True)


if __name__ == "__main__":
    main()
