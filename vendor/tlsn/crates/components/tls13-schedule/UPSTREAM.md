Port of `tlsnotary/tlsn` PR #1001, commit
`54b0efcd109edb08b01f152e9ba5de3112883e01` by themighty1.
Source: https://github.com/tlsnotary/tlsn/pull/1001
License: MIT OR Apache-2.0, as in TLSNotary.

This component uses alpha.15's `mpz v0.1.0-alpha.6`, rather than upgrading
the working TLS 1.2 stack to the older PR's TLSNotary API.
It is a key-schedule component, not a TLS 1.3 transport.

Local changes are tested against the original reference vectors. Handshake
traffic material is made available to both MPC participants so the notary
can authenticate the encrypted server handshake independently. Application
keys remain VM references. Only tests decode application keys.
