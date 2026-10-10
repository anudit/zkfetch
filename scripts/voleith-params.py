#!/usr/bin/env python3
"""Check FAEST-128 family layouts; never certify an exact 2^-128 bound.

The user selected nominal 128-bit security. This tool checks the implementation
layout against the pinned upstream parameters and reports the polynomial bound
separately. Composition/query-budget analysis remains a review requirement.
"""
import json
import math
from pathlib import Path

upstream = (Path(__file__).resolve().parent.parent / "vendor/faest/src/parameter.rs").read_text()
profiles = [("Fast", 8, 16, 8, 8, 8, 110, 3072),
            ("Small", 11, 11, 12, 11, 0, 102, 22528)]
results = []
for name, label, tau, k, tau0, tau1, t_open, leaves in profiles:
    block = upstream.split(f"impl TauParameters for Tau128{name} {{", 1)[1].split("}", 1)[0]
    expected = [f"type Tau = U{tau};", f"type K = U{k};", f"type Tau0 = U{tau0};",
                f"type Tau1 = U{tau1};", f"type Topen = U{t_open};", f"const L: usize = {leaves};"]
    assert all(value in block for value in expected), f"upstream parameter drift: {name}"
    assert tau0 + tau1 == tau
    challenge_bits = tau0 * (k - 1) + tau1 * k
    grinding_bits = 128 - challenge_bits
    assert grinding_bits == (8 if name == "Fast" else 7)
    assert leaves == tau0 * 2**(k - 1) + tau1 * 2**k
    results.append(dict(family=f"FAEST-128{'f' if name == 'Fast' else 's'}", protocol_label=label,
                        nominal_security_bits=128, field_bits=128, degree=3,
                        isolated_polynomial_bound_bits=128-math.log2(3),
                        tau=tau, challenge_bits=challenge_bits, grinding_bits=grinding_bits,
                        leaves=leaves, opening_bytes=tau*48+t_open*16))
print(json.dumps(dict(scope="layout consistency, not a full security certificate",
                     exact_total_error_le_2_to_minus_128_certified=False,
                     generalized_relation_composition_review_required=True,
                     profiles=results), indent=2))
