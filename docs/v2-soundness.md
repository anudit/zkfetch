# v2 soundness audit and release certificate

10 October 2026. **The current implementation is not certified to the completion
plan's exact 128-bit bounds.** External review is deferred. This audit does not
replace a security reduction or set unknown terms to zero.

```sh
python3 scripts/soundness.py
python3 scripts/soundness.py --require-release
```

The first command reproduces nominal upstream parameter layouts and reports
known check bounds. The release command deliberately fails until every term is
derived and the selected implementation meets the target. Do not remove that
failure by rounding 126-bit figures to nominal 128-bit security.

## Session check

The authenticated bridge homogenizes degree ≤3 relations into degree-three
polynomials and checks a masked polynomial at the secret MAC correlation Δ.
For a nonzero degree-three difference polynomial, the root-count upper bound is
three divided by the challenge support size. MPZ's `Delta::new` fixes its least
significant bit to one for its pointer-bit encoding. Its support is therefore
2^127, not 2^128. The isolated bound is at most 3/2^127, or about 125.415 bits;
a tighter argument would have to prove which difference polynomials an attacker
can realize under the MAC scheme.

Two independently weighted checks at the **same Δ do not generally square this
bound**: a common root of the malicious relation polynomials passes both. An
implementation claiming repetition must use genuinely independent authenticated
challenges (and prove the same witness is bound across them), or derive a tighter
scheme-specific theorem. Sampling another public coefficient seed alone does
not satisfy that obligation. Additional full correlations affect pool budgets,
setup and memory and must be included in measurements.

The ChaCha8 coefficient stream replaces per-constraint SHA-256 hashing. It
keeps pseudorandom individual coefficients, not seed powers. Its PRG advantage
belongs in the composition bound; a runtime correctness test is not an analysis
of that advantage.

## Offline degree-three adaptation

Fast and Small use upstream FAEST-128 BAVC layouts with their existing grinding
restrictions. That validates layout consistency, not inheritance of FAEST's
signature theorem by this general relation. The degree-three per-oracle-query
candidate is 3/2^128 before additional margin, rather than 1/2^128. Valid opening
challenges are restricted by grinding; account for conditional challenge support
and all failed hash trials in the reduction. Merely forcing more bits of Δ to
zero does not automatically reduce the root probability.

A possible margin is an independent grinding predicate on additional hash output
bits, separate from the Δ domain restriction. It requires a reduction for the
combined relation/BAVC and adversarial oracle-query accounting before being
certified. Higher τ and genuinely independent checks are alternatives with
measured size/time cost. No parameter change is certified by this document.

## Terms required before release

Derive and sum exact terms, with a stated query/session budget or the plan's
Q-scaled non-interactive notion:

- Malicious OT and regular-LPN/Ferret concrete security, including repeated pools.
- MAC/degree-three checks and witness consistency across independent repetitions.
- BAVC openings, VOLE consistency, grinding and Fiat–Shamir extraction.
- Hash collision and PRG distinguishing advantages for all primitives used.
- Bao openings, attestation signatures, key-commitment binding and parser semantics.
- Split ECtF/MtA, malicious garbling, authenticated output routing, and GCM's
  record/block-dependent forgery term under the actual reveal order.

The GHASH IR differential validates field encoding and computation only. It
neither certifies an authentication theorem nor authenticates provenance by
itself. Cipher suite and security assumptions must be explicit; hybrid key
exchange does not turn classical TLS certificate authentication into PQ security.

## Closure investigation: a protocol change is necessary

The 10 October follow-up closes the question of whether a coefficient-only
margin can meet the session target: **it cannot**. This is a lower-bound
obstruction, not just a loose application of a polynomial upper bound.

In the ideal MAC model write a bit authentication as `M = K + x·Δ`. A prover
that guesses Δ obtains the matching verifier keys for its known inputs and can
compute checks for a false relation. MPZ samples Δ from the odd field elements,
so a uniform guess succeeds with probability at least `1/2^127`. This exceeds
the requested `1/2^128` before adding OT, batching, or any other error term.

A concrete algebraic counterexample is the unsatisfiable relation `1 = 0`.
Homogenization makes its verifier polynomial `X^3`. Sending the constant
`g^3` passes at `Δ = g`, where `g` is a guessed odd element. Honest masking
only translates both sides by a lower-degree polynomial. Additional public
coefficient checks at the same Δ retain that root. The regression
`guessing_the_secret_delta_can_pass_a_false_constant_relation` checks this
counterexample and pins the constructor's pointer-bit behavior. It is not a
network exploit or a claim that the checked-witness API emits false proofs.

Under ideal independent uniform batch weights and a hidden uniform Δ, the
single bridge check has the conservative bound

```
Pr[false check accepts] ≤ 1/2^128 + 3/2^127 = 7/2^128.
```

The first term is cancellation of the leading residual coefficient: condition
on all but one coefficient of a nonzero residual vector, and exactly one value
of the remaining coefficient cancels it. Otherwise the resulting nonzero
polynomial has at most three roots in the 2^127-element challenge support.
This is an ideal-model lemma, not the complete Fiat–Shamir session theorem;
the real PRG/transcript, earlier boolean checks and OT terms remain separate.

**Required session margin:** use wider authentication throughout the session,
or two independently authenticated lanes with independent secret deltas.
Two independent root events alone would give `9/2^254`, but that is not a
certificate: both lanes must bind the same witness, include the earlier TLS
schedule/authentication checks, and preserve independence under adaptive
transcripts and failures. Merely copying the final bridge or adding a second
seed is insufficient. This changes correlation provisioning and the TLS VM,
so it must be implemented and remeasured before claiming D3-2 complete.

**Offline margin:** two additional independent grind bits would reduce the
isolated raw-opening root term to `3/2^130`. They must be separate hash-output
bits, not further restrictions on the existing Δ domain. This leaves only
`1/2^130` of the requested per-query budget for every other term, and does not
amplify a bad earlier consistency or batching challenge. Therefore it is not
an adequate selection until the full round-by-round reduction is established.
No extra grind bits have been deployed as a supposed full fix.

The [FAEST v2 specification](https://faest.info/faest-spec-v2.0.pdf), §9.5,
accounts separately for commitment extraction, leaf collisions and the
round-by-round proof error. Its signature theorem has additional assumptions
on relation and witness dimensions. The dynamic general-relation adapter does
not establish those assumptions simply by selecting the same Fast/Small tree
layouts. The audit reports these obligations rather than importing the
signature theorem unchanged.

The release checker still fails deliberately. Presentation parameter/size
optimizations remain paused while the authentication margin and generalized
reduction are unresolved. Neither nominal upstream labels nor an unreviewed
repetition argument are recorded as exact 128-bit security.

## Option A implementation boundary

The experimental full-entropy dual-lane kernel, VM, degree-three bridge and
paired Ferret pool now pass functional and mutation tests. FLOW5 source selects
both lanes throughout proxy TLS schedule checks and the application-key bridge
for v2 attestations. Its signed setup rejects a downgrade before upstream
forwarding, separates pool scopes by authentication mode and doubles admission
accounting. Snapshot `7066a4a` is now synchronously rebuilt and deployed; its native
cold/warm tests and hosted shipped-extension checks pass. See `v2-option-a-progress.md`.

With full 128-bit deltas, an isolated lane's ideal root/cancellation union is
`(3 + 1)/2^128`. Squaring would give `16/2^256` **only after** proving the
necessary independence under a malicious prover and the joint adaptive
transcript. Shared honest witness structs and two passing tests do not prove
that premise. A malicious prover controls both correction vectors. Every lane
must independently enforce the same complete public TLS relation, and the
reduction must address cross-lane witness consistency and adaptive leakage.
This candidate is not added to a certified total. OT, LPN, PRG/hash advantages
and offline extraction remain unresolved; `--require-release` still fails.

## Offline margin: per-round proof-of-work (11 October 2026)

The offline (VOLE-in-the-head) proof now meets **≤ Q·2⁻¹²⁸ for Q ≤ 2⁶⁴
random-oracle queries** by derivation. `scripts/soundness.py` reports
`offline.derived = true`: 2⁻¹²⁹·⁰ per query for Fast and 2⁻¹²⁹·¹ for Small.

**Mechanism.** Each Fiat–Shamir round gets an independent proof-of-work.
The predicate is evaluated on hash output disjoint from the challenge itself,
so it does not restrict the challenge distribution. Every *accepted*
challenge then costs an adversary 2^w oracle queries, which divides that
round's round-by-round error by 2^w. This differs from narrowing Δ's domain,
which does not reduce the root probability (see above). Constants are in
`crates/zkf-voleith/src/experimental.rs`:

| Round | Error before | PoW bits | Error per query |
|---|---|---:|---|
| iv → leaf-commitment hash key (FAEST Thm 9.24, third term) | τ·2⁻¹²⁸ | 7 | τ·2⁻¹³⁵ |
| VOLE consistency (Lemma 4.10, incl. SoftSpoken 2^τ loss, ℓ̂ ≤ 2²³) | 2^τ·2⁻¹⁴⁴ | 2 | ≤ 2⁻¹³⁰ |
| Check weights (independent uniform field weights) | 2⁻¹²⁸ | 2 | 2⁻¹³⁰ |
| Opening Δ (degree-3 roots) | 3·2⁻¹²⁸ | 3 | 3·2⁻¹³¹ |
| Oracle collisions (2λ-bit outputs) | Q·2⁻²⁵⁶ | — | ≤ 2⁻¹⁹² at Q = 2⁶⁴ |

The total is leaf + max(round) + collision. Rounds combine by their maximum,
because Fiat–Shamir of a round-by-round sound protocol loses a factor of Q on
the largest round error (Canetti et al., STOC 2019).

**Cost.** Expected extra hashing per proof: 128 iv trials, 4 + 4 nonces, and
an 8× wider Δ search. The Δ search checks the cheap predicate before the BAVC
opening, so the number of openings is unchanged. Measured prove/verify times
are within run-to-run noise of the previous build. Proofs grow by 8 bytes,
for the two u32 nonces. The proof magic is `zkfVI\0\x03\0`, and the transcript
domain is `pow-margin-2`. Older proofs are rejected.

**What this does not cover.**
- The term structure is FAEST v2 Theorem 9.24 applied to a general degree-3
  relation. Re-proving it independently for our relation is part of the
  deferred external review.
- Attestation-side terms (ECDSA, Bao/BLAKE3, `C_k` binding) and the session
  terms below remain separate entries in `unresolvedTerms`.
