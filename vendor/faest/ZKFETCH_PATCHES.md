# zkfetch primitive adapter

Upstream: https://github.com/ait-crypto/faest-rs
Commit: `9ccc68c06f2db762b91afc06b20826d5836d477a`, package 0.3.0.
Original Apache-2.0/MIT licenses are preserved.

The upstream signature implementation is retained unchanged. `zkfetch.rs`
exposes a bounded dynamic-length adapter around the existing FAEST-128 BAVC,
PRG, VOLE conversion and universal hash primitives. It is not a general
statement proof by itself. Upstream's compile-time VOLE implementation stays
available as a differential oracle. The standalone workspace omits the
unvendored benchmark package.

The wrapper uses upstream native AES PRGs on every architecture for now;
there is no ChaCha8 wasm variant yet. Public parameter labels 8/11 identify
FAEST-128f/128s; upstream 128s represents depth 11 using `K=12, Tau1=0`.
Neither wrapper nor upstream is claimed externally reviewed.
