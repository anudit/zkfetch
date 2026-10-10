# V2 primitive fuzz targets

These targets exercise the implemented CBOR decoder, record tables, Bao
openings and the JSON **reference parser**. Presentation/VOLEitH decoders and
a constrained JSON circuit remain outstanding; these targets do not satisfy
the complete W7 release gate.

```
cargo +nightly install cargo-fuzz --locked
cargo run -p zkf-attestation --example fuzz_seeds
cargo +nightly fuzz run attestation_cbor -- -max_total_time=30 -max_len=65536
cargo +nightly fuzz run record_table_bao -- -max_total_time=30 -max_len=65536
cargo +nightly fuzz run json_anchors -- -max_total_time=30 -max_len=65536
```

Retain any generated reproducer in a regression test before fixing the code.
Corpus and artifact directories are ignored; the separately generated fuzz
lockfile should be retained for reproducible dependencies.

The seed generator emits synthetic public statements, including both allowed
transcript-hash widths and the JSON quote-parity counterexample. It never
reads device secrets or real attestations.
