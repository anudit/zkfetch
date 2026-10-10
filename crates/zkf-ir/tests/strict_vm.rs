#![cfg(feature = "mpz-backend")]
use mpz_circuits::CircuitBuilder;
use mpz_common::context::test_st_context;
use mpz_core::Block;
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core::{memory::binary::U8, prelude::*, Call};
use mpz_zk::{
    strict::{Prover, Verifier, ZkDelta},
    ProverConfig, VerifierConfig,
};
use std::sync::Arc;

#[tokio::test]
async fn dual_vm_composes_private_inputs_gates_and_public_openings() {
    let mut builder = CircuitBuilder::new();
    let a: Vec<_> = (0..8).map(|_| builder.add_input()).collect();
    let b: Vec<_> = (0..8).map(|_| builder.add_input()).collect();
    for i in 0..8 {
        let z = builder.add_and_gate(a[i], b[i]);
        let z = builder.add_inv_gate(z);
        builder.add_output(z);
    }
    let circ = Arc::new(builder.build().unwrap());
    // Include an even delta, which would be altered by the legacy pointer-bit type.
    let deltas = [
        ZkDelta::new(Block::new([42; 16])),
        ZkDelta::new(Block::new([97; 16])),
    ];
    let (s0, r0) = ideal_rcot(Block::new([11; 16]), *deltas[0].as_block());
    let (s1, r1) = ideal_rcot(Block::new([12; 16]), *deltas[1].as_block());
    let mut p = Prover::new(ProverConfig::default(), [r0, r1]);
    let mut v = Verifier::new(VerifierConfig::default(), deltas, [s0, s1]);
    p.bind_statement(b"same TLS-like chained relation");
    v.bind_statement(b"same TLS-like chained relation");
    let ap: U8 = p.alloc().unwrap();
    let av: U8 = v.alloc().unwrap();
    let bp: U8 = p.alloc().unwrap();
    let bv: U8 = v.alloc().unwrap();
    p.mark_private(ap).unwrap();
    v.mark_blind(av).unwrap();
    p.mark_public(bp).unwrap();
    v.mark_public(bv).unwrap();
    p.assign(ap, 173u8).unwrap();
    p.assign(bp, 207u8).unwrap();
    v.assign(bv, 207u8).unwrap();
    p.commit(ap).unwrap();
    v.commit(av).unwrap();
    p.commit(bp).unwrap();
    v.commit(bv).unwrap();
    let xp: U8 = p
        .call(Call::builder(circ.clone()).arg(ap).arg(bp).build().unwrap())
        .unwrap();
    let xv: U8 = v
        .call(Call::builder(circ.clone()).arg(av).arg(bv).build().unwrap())
        .unwrap();
    // A second call borrows the first call's authentication rather than reassigning it.
    let yp: U8 = p
        .call(Call::builder(circ.clone()).arg(xp).arg(bp).build().unwrap())
        .unwrap();
    let yv: U8 = v
        .call(Call::builder(circ).arg(xv).arg(bv).build().unwrap())
        .unwrap();
    let mut dp = p.decode(yp).unwrap();
    let mut dv = v.decode(yv).unwrap();
    let (mut cp, mut cv) = test_st_context(8);
    let (pr, vr) = futures::join!(p.execute_all(&mut cp), v.execute_all(&mut cv));
    pr.unwrap();
    vr.unwrap();
    let expected = !(!(173u8 & 207u8) & 207u8);
    assert_eq!(dp.try_recv().unwrap().unwrap(), expected);
    assert_eq!(dv.try_recv().unwrap().unwrap(), expected);
    assert_eq!(p.field_challenge(), v.field_challenge());
    for (m, k) in p.get_macs(yp).unwrap().iter().zip(v.get_keys(yv).unwrap()) {
        assert!(k.authenticates(m, &deltas));
    }
}

#[tokio::test]
async fn strict_cubic_bridge_rejects_reassigned_borrowed_values_and_statement_changes() {
    use zkf_ir::{backend::mpz::strict, field::Fe, Circuit, Term};
    for (actual, p_statement, reject) in [
        (7u8, b"same".as_slice(), false),
        (8, b"same".as_slice(), true),
        (7, b"changed".as_slice(), true),
    ] {
        let mut c = Circuit::default();
        let byte = c.commit_byte();
        let x = c.lift(byte);
        c.assert_zero(vec![
            Term::Cubic(Fe::ONE, x, x, x),
            Term::Constant(Fe::byte(7) * Fe::byte(7) * Fe::byte(7)),
        ]);
        let raw: Vec<_> = (0..8).map(|i| Fe(((7u8 >> i) & 1) as u128)).collect();
        let w = c.eval(&raw).unwrap();
        let deltas = [
            ZkDelta::new(Block::new([42; 16])),
            ZkDelta::new(Block::new([97; 16])),
        ];
        let (s0, r0) = ideal_rcot(Block::new([11; 16]), *deltas[0].as_block());
        let (s1, r1) = ideal_rcot(Block::new([12; 16]), *deltas[1].as_block());
        let mut p = Prover::new(ProverConfig::default(), [r0, r1]);
        let mut v = Verifier::new(VerifierConfig::default(), deltas, [s0, s1]);
        let ap: U8 = p.alloc().unwrap();
        let av: U8 = v.alloc().unwrap();
        p.mark_private(ap).unwrap();
        v.mark_blind(av).unwrap();
        p.assign(ap, actual).unwrap();
        p.commit(ap).unwrap();
        v.commit(av).unwrap();
        let (mut cp, mut cv) = test_st_context(8);
        let pp = [ap];
        let vp = [av];
        let (pr, vr) = futures::join!(
            strict::prove_prefixes(&mut p, &mut cp, &c, &w, &pp, p_statement),
            strict::verify_prefixes(&mut v, &mut cv, &c, &vp, b"same")
        );
        pr.unwrap();
        assert_eq!(vr.is_err(), reject);
        if !reject {
            assert_eq!(p.field_challenge(), v.field_challenge());
        }
    }
}
