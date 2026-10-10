#!/usr/bin/env python3
"""Summarize opt-in native fixture measurements, never witness/response data."""
import json
from pathlib import Path
from statistics import median


ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "docs/benchmarks/d1-d3-baseline"
# Known static circuit shapes (input bits, output bits, AND gates per call).
# Other shapes remain unclassified rather than guessing their semantic role.
SHAPES = {
    (128, 1408, 1280): "aes128_key_expansion",
    (256, 128, 6400): "aes128_full",
    (768, 256, 22573): "sha256",
    (1024, 512, 10416): "blake3",
    (1536, 128, 5120): "aes128_after_expansion",
}


def summarize(path):
    report = json.loads(path.read_text())
    rows = report["samples"]
    allocations = rows[0]["circuit_allocations"]
    if allocations is None:
        raise ValueError(f"{path}: rerun with --features circuit-metrics")
    if any(row["circuit_allocations"] != allocations for row in rows):
        raise ValueError(f"{path}: allocation shapes vary across samples")
    groups = {}
    for circuit in allocations["circuits"]:
        shape = tuple(circuit[k] for k in ["input_bits", "output_bits", "and_gates_per_call"])
        group = SHAPES.get(shape, "linear" if shape[2] == 0 else "unclassified")
        groups[group] = groups.get(group, 0) + shape[2] * circuit["calls"]
    assert sum(groups.values()) == allocations["allocated_and_gates"]
    return {
        "scenario": report["scenario"],
        "samples": len(rows),
        "median_presentation_prove_ms": median(row["presentation_prove_ms"] for row in rows),
        "median_presentation_verify_ms": median(row["presentation_verify_ms"] for row in rows),
        "offline_proof_bytes": sorted({row["offline_proof_bytes"] for row in rows}),
        "presentation_bytes": sorted({row["presentation_bytes"] for row in rows}),
        "private_input_bits": allocations["private_input_bits"],
        "allocated_and_gates": allocations["allocated_and_gates"],
        "allocated_bits_excluding_check_masks": allocations["private_input_bits"] + allocations["allocated_and_gates"],
        "and_gates_by_known_shape": groups,
        "warm_median_timings_ms": {
            key: median(row["timings"][key] for row in rows if row["timings"]["voleResumed"])
            for key in ["notaryConnectMs", "setupMs", "tlsMs", "proveMs", "attestMs", "totalMs"]
        },
    }


if __name__ == "__main__":
    summary = {
        "measurement_scope": "Native localhost, one cold and two resumed sessions per scenario. Presentation timers include transcript-proof building. QuickSilver scenarios carry signed session predicates, not an offline predicate proof.",
        "classification_caveat": "Known shapes only; GCM tags and JSON are not separately attributed. Allocation counters exclude check masks and do not measure consumed VOLE or peak RAM.",
        "scenarios": [summarize(DEST / name) for name in ["native.json", "native-quicksilver.json", "native-reveal.json"]],
    }
    (DEST / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
