use mpz_common::{Context, context::test_st_context};
use mpz_ideal_vm::IdealVm;
use mpz_vm_core::{
    Execute,
    memory::{Array, MemoryExt, ViewExt, binary::U8},
};
use zkf_tls13_schedule::{Mode, OrigoClaim, OrigoSchedule, Role, Tls13KeySched};

type Output = ([u8; 16], [u8; 12], [u8; 16], [u8; 12]);
fn hex_array<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).unwrap().try_into().unwrap()
}

async fn execute(
    vm: &mut IdealVm,
    ctx: &mut Context,
    claim: &OrigoClaim,
    hash: [u8; 32],
    witness: Option<[u8; 32]>,
) -> anyhow::Result<Output> {
    let mut schedule = OrigoSchedule::alloc(vm, witness.is_some())?;
    schedule.assign(vm, claim, hash, witness)?;
    let mut ck = vm.decode(schedule.keys.client_write_key)?;
    let mut ci = vm.decode(schedule.keys.client_iv)?;
    let mut sk = vm.decode(schedule.keys.server_write_key)?;
    let mut si = vm.decode(schedule.keys.server_iv)?;
    vm.execute_all(ctx).await?;
    schedule.verify(claim)?;
    Ok((
        ck.try_recv()?.unwrap(),
        ci.try_recv()?.unwrap(),
        sk.try_recv()?.unwrap(),
        si.try_recv()?.unwrap(),
    ))
}

async fn evaluate(claim: &OrigoClaim, hash: [u8; 32], witness: [u8; 32]) -> anyhow::Result<Output> {
    let (mut a, mut b) = (IdealVm::new(), IdealVm::new());
    let (mut ca, mut cb) = test_st_context(8);
    let (a, b) = futures::join!(
        execute(&mut a, &mut ca, claim, hash, Some(witness)),
        execute(&mut b, &mut cb, claim, hash, None),
    );
    let (a, b) = (a?, b?);
    assert_eq!(a, b);
    Ok(a)
}

#[tokio::test]
async fn rfc8448_section3_origo_known_answer() {
    // RFC 8448 §3, final version rather than the older draft vectors.
    let secret = hex_array("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    let hello = hex_array("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    let handshake = hex_array("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    let (claim, witness) = OrigoClaim::preprocess(&secret, hello, handshake);
    assert_eq!(
        claim.handshake_secrets(),
        (
            hex_array("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"),
            hex_array("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"),
        )
    );
    assert_eq!(
        evaluate(&claim, handshake, witness).await.unwrap(),
        (
            hex_array("17422dda596ed5d9acd890e3c63f5051"),
            hex_array("5b78923dee08579033e523d9"),
            hex_array("9f02283b6c9c07efc26bb9f2ac92e356"),
            hex_array("cf782b88dd83549aadf1e984"),
        )
    );
}

#[tokio::test]
async fn every_revealed_intermediate_mutation_changes_or_rejects_statement() {
    let secret = [7u8; 32];
    let hello = [8u8; 32];
    let handshake = [9u8; 32];
    let (claim, witness) = OrigoClaim::preprocess(&secret, hello, handshake);
    let expected = evaluate(&claim, handshake, witness).await.unwrap();
    for i in 0..7 {
        let mut encoded = bincode::serialize(&claim).unwrap();
        assert_eq!(encoded.len(), 7 * 32);
        encoded[i * 32] ^= 1;
        let bad: OrigoClaim = bincode::deserialize(&encoded).unwrap();
        let result = evaluate(&bad, handshake, witness).await;
        // Handshake-only intermediates are authenticated by server/client
        // Finished, outside this application-key circuit. Keep that
        // distinction explicit rather than pretending verify() checks them.
        assert!(
            result.is_err()
                || result.unwrap() != expected
                || bad.handshake_secrets() != claim.handshake_secrets(),
            "mutation {i}"
        );
    }
    let mut bad_witness = witness;
    bad_witness[0] ^= 1;
    assert!(evaluate(&claim, handshake, bad_witness).await.is_err());
    assert!(evaluate(&claim, [10; 32], witness).await.is_err());
}

async fn legacy(
    vm: &mut IdealVm,
    ctx: &mut Context,
    secret: [u8; 32],
    hello: [u8; 32],
    handshake: [u8; 32],
    prover: bool,
) -> Output {
    let pms: Array<U8, 32> = vm.alloc().unwrap();
    if prover {
        vm.mark_private(pms).unwrap();
        vm.assign(pms, secret).unwrap();
    } else {
        vm.mark_blind(pms).unwrap();
    }
    vm.commit(pms).unwrap();
    let mut schedule = Tls13KeySched::new(
        Mode::Normal,
        if prover { Role::Leader } else { Role::Follower },
    );
    schedule.alloc(vm, pms).unwrap();
    schedule.assign_all(vm, hello, handshake).unwrap();
    vm.execute_all(ctx).await.unwrap();
    let (_, keys) = schedule.finish_all().unwrap();
    let mut ck = vm.decode(keys.client_write_key).unwrap();
    let mut ci = vm.decode(keys.client_iv).unwrap();
    let mut sk = vm.decode(keys.server_write_key).unwrap();
    let mut si = vm.decode(keys.server_iv).unwrap();
    vm.execute_all(ctx).await.unwrap();
    (
        ck.try_recv().unwrap().unwrap(),
        ci.try_recv().unwrap().unwrap(),
        sk.try_recv().unwrap().unwrap(),
        si.try_recv().unwrap().unwrap(),
    )
}

#[tokio::test]
async fn direct_differential_against_legacy_normal_circuit() {
    for seed in [0, 1, 127, 255] {
        let secret = [seed; 32];
        let hello = [seed ^ 0x55; 32];
        let handshake = [seed ^ 0xaa; 32];
        let (claim, witness) = OrigoClaim::preprocess(&secret, hello, handshake);
        let optimized = evaluate(&claim, handshake, witness).await.unwrap();
        let (mut a, mut b) = (IdealVm::new(), IdealVm::new());
        let (mut ca, mut cb) = test_st_context(8);
        let (a, b) = futures::join!(
            legacy(&mut a, &mut ca, secret, hello, handshake, true),
            legacy(&mut b, &mut cb, secret, hello, handshake, false),
        );
        assert_eq!(a, b);
        assert_eq!(a, optimized, "seed {seed}");
    }
}
