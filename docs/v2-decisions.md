# v2 completion decisions

Accepted 10 October 2026 in `comptest/zkfetch-d1-d5-completion-plan.md`.
Implementation baseline: `00c9be5`. These decisions describe the intended release;
they are not claims that the implementation already meets the release gates.

1. **Presentation budgets.** On a 1 KiB JSON body, signed-head targets ≤25 KiB
   and ≤100 ms proving in Chrome with eight threads. Ciphertext-only targets
   ≤40 KiB and ≤150 ms. Publish scaling per KiB of JSON prefix above that size.
   Parser context starts at the document boundary; the former T2 anchor shortcut
   is excluded because it does not establish JSON parser context.
2. **Signed-head default, gated.** Make signed response headers the default only
   after v2 signed-head notarization is no slower than v1 FLOW3 at 33 and 100 ms
   simulated RTT. Keep ciphertext-only available for header privacy. The current
   default remains unchanged until that gate passes.
3. **Derived soundness, not nominal labels.** For non-interactive proofs the
   target is success ≤Q·2⁻¹²⁸ for Q random-oracle queries; for a designated-verifier
   session it is ≤2⁻¹²⁸ per session. Count polynomial degree, VOLE/LPN, BAVC,
   grinding, Fiat–Shamir and hash terms explicitly. Choose and measure the margin
   needed to close any deficit. Independent pseudorandom check coefficients
   remain required; seed powers are excluded. D5 must also account for garbling,
   ECtF/MtA and the record/block-dependent GHASH term. The existing parameter
   script checks nominal layouts and does not certify this new target.
4. **Hybrid key exchange.** Prefer X25519MLKEM768 in proxy and split modes;
   retain classical fallbacks and sign the negotiated group. Add verifier policy
   requiring the hybrid. Proxy decapsulates locally; split supplies the ML-KEM
   secret as a prover-private garbled-circuit input. Split still needs shared
   X25519 through ECtF. Verify the Wei25519 coordinate/share conversion and
   malformed-point handling before adopting it. Hybrid privacy is intended to
   survive later quantum compromise; split soundness still assumes no real-time
   quantum attack on X25519. Classical server certificates do not become
   post-quantum authentication through this change.
5. **JSON paths.** Support exact root-to-leaf paths with object keys and array
   indices to depth eight, rather than matching any occurrence of a final key.
   Optional uniqueness requires checking the enclosing suffixes. Re-enable
   Duolingo v2 only after those semantics are implemented and tested.
6. **Modes and preparation.** Proxy is the intended default; split is opt-in or
   selected by verifier `requireSplit` policy. Prepare garbling, ECtF/MtA and
   label OT ahead of the click path. Prepare in the extension on Wi-Fi by
   default, with configuration. Include three-halves garbling in the split
   implementation. Prepared split should take at most proxy +0.5 s in Chrome
   at 33 ms RTT; report unprepared latency without a target.

Release additionally requires the complete benchmark/test matrix, documented
security arguments, checked models and external review. No production default
should imply those reviews or bounds have already been completed.
