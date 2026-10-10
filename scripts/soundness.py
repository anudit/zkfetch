#!/usr/bin/env python3
"""Reproduce current check bounds and fail closed for the v2 release certificate.

This is an audit entry point, not a proof that unresolved composition terms are
zero. --require-release rejects any unknown term or bound above the target.
"""
import argparse
from fractions import Fraction
import json
import math
import re
from pathlib import Path
import subprocess
import sys


def term(name, numerator, denominator_bits, source):
    bound = Fraction(numerator, 2**denominator_bits)
    return {"name": name, "numerator": str(bound.numerator),
            "denominator": str(bound.denominator),
            "boundBits": denominator_bits - math.log2(numerator), "source": source}


def rust_const(path, name):
    match = re.search(rf"pub const {name}: u32 = (\d+);", path.read_text())
    if not match:
        raise SystemExit(f"missing {name} in {path}")
    return int(match.group(1))


def offline_bound(root):
    """Per-random-oracle-query error of the offline (VOLE-in-the-head) proof.

    Follows the term structure of FAEST v2 Theorem 9.24 / §9.1.3, applied to
    our general degree-3 relation, with every round given an independent
    proof-of-work (experimental.rs POW_* constants):
      leaf:        tau * 2^-lambda per iv query, divided by 2^POW_IV_BITS
      consistency: 2^tau (SoftSpoken loss) * eps_v, eps_v from Lemma 4.10
                   generalised to l_hat <= 8*MAX_VECTOR_BYTES, / 2^POW_CONSISTENCY_BITS
      weights:     2^-lambda (independent uniform weights cancel a nonzero
                   residual), / 2^POW_WEIGHTS_BITS
      opening:     d * 2^-lambda roots of the degree-3 check, / 2^POW_OPENING_BITS
      collisions:  Q / 2^(2*lambda) per query for 2*lambda-bit oracle outputs
    Fiat-Shamir of a round-by-round sound protocol loses Q * max(round error)
    (Canetti et al., STOC'19), so rounds contribute their maximum, while the
    leaf and collision terms are added.
    """
    src = root / "crates/zkf-voleith/src/experimental.rs"
    w = {k: rust_const(src, k) for k in
         ("POW_IV_BITS", "POW_CONSISTENCY_BITS", "POW_WEIGHTS_BITS", "POW_OPENING_BITS")}
    lam, B, degree, query_bits = 128, 16, 3, 64
    max_vector_bytes = int(re.search(r"MAX_VECTOR_BYTES: usize = 1 << (\d+)",
        (root / "vendor/faest/src/zkfetch.rs").read_text()).group(1))
    l_hat = 8 * 2**max_vector_bytes
    eps_v = Fraction(l_hat**2, 2**(lam + 76)) + Fraction(1, 2**(lam + B))
    sets = {}
    for name, tau in (("Fast", 16), ("Small", 11)):
        leaf = Fraction(tau, 2**(lam + w["POW_IV_BITS"]))
        rounds = {
            "consistency": 2**tau * eps_v / 2**w["POW_CONSISTENCY_BITS"],
            "weights": Fraction(1, 2**(lam + w["POW_WEIGHTS_BITS"])),
            "opening": Fraction(degree, 2**(lam + w["POW_OPENING_BITS"])),
        }
        collision = Fraction(2**query_bits, 2**(2 * lam))
        total = leaf + max(rounds.values()) + collision
        bits = lambda x: -math.log2(x)
        sets[name] = {"tau": tau, "leafBits": bits(leaf),
                      "roundBits": {k: bits(v) for k, v in rounds.items()},
                      "collisionBitsAtQ2^64": bits(collision),
                      "perQueryBits": bits(total), "meets": total <= Fraction(1, 2**lam)}
    return {"notion": "success <= Q * 2^-128 for Q <= 2^64 random-oracle queries",
            "powBits": w, "maxCommittedBits": l_hat, "parameterSets": sets,
            "derived": all(v["meets"] for v in sets.values()),
            "caveat": "term structure adapted from FAEST v2 Thm 9.24 to a general degree-3 relation; "
                      "independent review of that adaptation is deferred"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-release", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    layout = json.loads(subprocess.check_output([sys.executable, str(root / "scripts/voleith-params.py")], text=True))
    # The degree-3 root bound is stated independently of any claimed FAEST
    # reduction. MPZ restricts the pointer bit, reducing support to 2^127.
    terms = [term("session.degree3.root", 3, 127,
                  "mpz memory-core correlated.rs: Delta::new fixes LSB to one"),
             term("offline.degree3.perOracleQuery.candidate", 3, 128,
                  "experimental.rs degree-three check; candidate requiring FS reduction"),
             term("session.independentWeightCancellation.ideal", 1, 128,
                  "one nonzero residual, conditioned on independent uniform coefficients")]
    unresolved = [
        "session MAC/pointer-bit reduction and independent-delta repetition",
        "Ferret regular-LPN concrete security and composed malicious OT terms",
        "ChaCha8 check-coefficient PRG advantage",
        "BLAKE3/Bao, SHA-256 and TurboSHAKE128 collision/query budgets",
        "split ECtF/MtA, malicious garbling and output-authentication composition",
        "split GCM record/block-dependent authentication error",
    ]
    session_check = Fraction(3, 2**127) + Fraction(1, 2**128)
    margin = {
        "currentSessionCheckUpperBoundIdeal": {"numerator": str(session_check.numerator),
            "denominator": str(session_check.denominator), "boundBits": 128-math.log2(7)},
        "sessionDeltaGuessLowerBound": {"numerator": "1", "denominator": str(2**127)},
        "sameDeltaCoefficientRepetitionsCloseGap": False,
        "minimumIndependentDeltaLanesForRootTerm": 2,
        "twoLaneRootOnlyConditionalBound": {"numerator": "9", "denominator": str(2**254)},
        "twoLaneBoundCertified": False,
        "strictKernelImplemented": True,
        "strictVmAndBridgeImplemented": True,
        "pairedFullEntropyFerretTested": True,
        "productionStrictLanesSelected": True,
        "strictProtocol": "FLOW5 / attestation-v2 / two independent full-width lanes",
        "deployedStrictLanesSelected": True,
        "deployedStrictSnapshot": "7066a4a",
        "fullEntropyTwoLaneRootAndCancellationCandidate": {
            "numerator": "16", "denominator": str(2**256),
            "certified": False,
            "condition": "adaptive conditional independence of both complete lanes must be proved",
        },
        "twoLaneConditions": ["independent MAC deltas and OT correlations",
            "same witness bound across lanes and all earlier TLS schedule checks",
            "adaptive transcript and reset composition analysed"],
        "offlineRootOnlyMinimumIndependentGrindingBits": 2,
        "offlineRootWithTwoIndependentBits": {"numerator": "3", "denominator": str(2**130)},
        "offlineGrindingCertified": "see offline.derived",
        "selection": "wider authentication or independent complete authentication lanes in session; no deployed margin certified",
    }
    offline = offline_bound(root)
    report = {"targetBits": 128, "marginAnalysis": margin, "offline": offline, "nominalLayout": layout,
              "checkTerms": terms, "unresolvedTerms": unresolved,
              "releaseCertified": False,
              "reason": "FLOW5 implements full-entropy dual lanes; adaptive composition, offline reduction and concrete primitive terms remain unresolved"}
    print(json.dumps(report, indent=2))
    if args.require_release:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
