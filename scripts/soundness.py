#!/usr/bin/env python3
"""Reproduce current check bounds and fail closed for the v2 release certificate.

This is an audit entry point, not a proof that unresolved composition terms are
zero. --require-release rejects any unknown term or bound above the target.
"""
import argparse
from fractions import Fraction
import json
import math
from pathlib import Path
import subprocess
import sys


def term(name, numerator, denominator_bits, source):
    bound = Fraction(numerator, 2**denominator_bits)
    return {"name": name, "numerator": str(bound.numerator),
            "denominator": str(bound.denominator),
            "boundBits": denominator_bits - math.log2(numerator), "source": source}


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
        "BAVC opening/grinding reduction for the generalized degree-three relation",
        "Fiat-Shamir query accounting and independent margin-grinding reduction",
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
        "twoLaneConditions": ["independent MAC deltas and OT correlations",
            "same witness bound across lanes and all earlier TLS schedule checks",
            "adaptive transcript and reset composition analysed"],
        "offlineRootOnlyMinimumIndependentGrindingBits": 2,
        "offlineRootWithTwoIndependentBits": {"numerator": "3", "denominator": str(2**130)},
        "offlineGrindingCertified": False,
        "selection": "wider authentication or independent complete authentication lanes in session; no deployed margin certified",
    }
    report = {"targetBits": 128, "marginAnalysis": margin, "nominalLayout": layout,
              "checkTerms": terms, "unresolvedTerms": unresolved,
              "releaseCertified": False,
              "reason": "single 127-bit MAC delta admits a guessing attack above target; composition and the required protocol upgrade remain unresolved"}
    print(json.dumps(report, indent=2))
    if args.require_release:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
