# ORIGO SHA-256 compression accounting

The implemented AES-128/SHA-256 application relation uses **16 compressions**,
compared with 32 in the legacy full schedule: a 50% reduction.
The earlier architecture estimate of approximately 14 did not include both
additional IV outputs in the key-only count.

The accounting below follows `OrigoSchedule::alloc` in
`vendor/tlsn/crates/components/tls13-schedule/src/origo.rs`.

| In-circuit operation | Compressions |
|---|---:|
| Finish derived handshake secret from public HS outer state and private inner-hash witness | 1 |
| Build derived-secret inner and outer pad states | 2 |
| Finish master secret from its supplied inner hash | 1 |
| Build master-secret inner and outer pad states | 2 |
| Finish client and server application traffic secrets | 2 |
| Build inner and outer pad states for both application traffic secrets | 4 |
| Finish client and server application keys | 2 |
| Finish client and server IVs | 2 |
| **Total** | **16** |

Each supplied downstream inner pad is decoded and checked against the pad
computed from its private parent secret before signing. Application keys,
application secrets and downstream outer pad states remain private. The public
IVs are outputs of this same relation.

The ORIGO seven-compression per-key figure corresponds to a key-only branch:
the common derived/master prefix costs six, then a direction contributes one
traffic-secret output, two traffic-secret pads, and one key output. For both
keys this is six plus two times four, or fourteen; retaining a checked IV in
each direction adds two. A single key-only branch in this implementation is
therefore ten compressions, not a literal seven; differences in shared prefix,
revealed boundary and output obligations must be stated when comparing circuits.
This note does not assert that ORIGO's original relation is identical.

The current proxy relation starts from public HS outer state and a private
inner-hash witness; it does not recompute ECDHE extraction in circuit. Handshake
traffic inner hashes are authenticated through Finished verification outside
this application relation. Mutation tests distinguish those boundaries rather
than claiming that the application-pad check rejects every handshake mutation.

The 64-byte hybrid-IKM extraction estimate (+one compression) belongs to the
future hybrid/split schedule, and is not included in this implemented count.
SHA-384 and split schedules need their own counts. Key commitments and response
head/claim circuits are additional work and are excluded here.

Run the RFC 8448, legacy differential and intermediate-class mutation checks:

```sh
bash scripts/check-origo.sh
```

The original architecture file is outside this repository. Until its estimate
is reconciled there, this implementation accounting takes precedence for
benchmark comparisons.
