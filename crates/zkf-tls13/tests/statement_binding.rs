use mpz_circuits::AES128;
use mpz_common::context::test_st_context;
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core::{
    Call,
    memory::{Array, binary::U8, correlated::Delta},
    prelude::*,
};
use mpz_zk::{Prover, ProverConfig, Verifier, VerifierConfig};
use rand::{Rng, SeedableRng, rngs::StdRng};
async fn run(prover_parts: &[&[u8]], verifier_parts: &[&[u8]], public_message: u8, valid: bool) {
    let mut rng = StdRng::seed_from_u64(3);
    let delta = Delta::random(&mut rng);
    let (sender, receiver) = ideal_rcot(rng.random(), delta.into_inner());
    let (mut cp, mut cv) = test_st_context(8);
    let mut p = Prover::new(ProverConfig::default(), receiver);
    let mut v = Verifier::new(VerifierConfig::default(), delta, sender);
    for part in prover_parts {
        p.bind_statement(part);
    }
    for part in verifier_parts {
        v.bind_statement(part);
    }
    let pk: Array<U8, 16> = p.alloc().unwrap();
    let pm: Array<U8, 16> = p.alloc().unwrap();
    let vk: Array<U8, 16> = v.alloc().unwrap();
    let vm: Array<U8, 16> = v.alloc().unwrap();
    p.mark_private(pk).unwrap();
    p.mark_public(pm).unwrap();
    v.mark_blind(vk).unwrap();
    v.mark_public(vm).unwrap();
    p.assign(pk, [7; 16]).unwrap();
    p.assign(pm, [42; 16]).unwrap();
    v.assign(vm, [public_message; 16]).unwrap();
    p.commit(pk).unwrap();
    p.commit(pm).unwrap();
    v.commit(vk).unwrap();
    v.commit(vm).unwrap();
    let po: Array<U8, 16> = p
        .call(
            Call::builder(AES128.clone())
                .arg(pk)
                .arg(pm)
                .build()
                .unwrap(),
        )
        .unwrap();
    let vo: Array<U8, 16> = v
        .call(
            Call::builder(AES128.clone())
                .arg(vk)
                .arg(vm)
                .build()
                .unwrap(),
        )
        .unwrap();
    let mut pd = p.decode(po).unwrap();
    let mut vd = v.decode(vo).unwrap();
    let (pr, vr) = futures::join!(p.execute_all(&mut cp), v.execute_all(&mut cv));
    pr.unwrap();
    if valid {
        vr.unwrap();
        assert_eq!(
            pd.try_recv().unwrap().unwrap(),
            vd.try_recv().unwrap().unwrap()
        );
    } else {
        assert!(vr.is_err());
    }
}
#[tokio::test]
async fn bound_statement_accepts_matching_proof() {
    run(
        &[b"lease", b"TLS transcript"],
        &[b"lease", b"TLS transcript"],
        42,
        true,
    )
    .await;
}
#[tokio::test]
async fn changed_statement_or_public_input_fails() {
    run(
        &[b"lease", b"TLS transcript"],
        &[b"other lease", b"TLS transcript"],
        42,
        false,
    )
    .await;
    run(&[b"a", b"bc"], &[b"ab", b"c"], 42, false).await;
    run(&[b"same"], &[b"same"], 43, false).await;
}
