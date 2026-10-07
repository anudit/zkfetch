use super::*;
use aes_gcm::{
    Aes128Gcm, KeyInit,
    aead::{Aead as _, Payload},
};
use mpz_common::context::test_st_context;
use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
use mpz_ot::ideal::cot::ideal_cot;
use mpz_vm_core::memory::correlated::Delta;
use rand::{SeedableRng, rngs::StdRng};

fn shared(vm: &mut dyn Vm<Binary>, data: &[u8], leader: bool) -> Vector<U8> {
    let a: Vector<U8> = vm.alloc_vec(data.len()).unwrap();
    let b: Vector<U8> = vm.alloc_vec(data.len()).unwrap();
    if leader {
        vm.mark_private(a).unwrap();
        vm.assign(a, data.iter().map(|b| b ^ 0xa5).collect::<Vec<_>>())
            .unwrap();
        vm.mark_blind(b).unwrap();
    } else {
        vm.mark_blind(a).unwrap();
        vm.mark_private(b).unwrap();
        vm.assign(b, vec![0xa5; data.len()]).unwrap();
    }
    vm.commit(a).unwrap();
    vm.commit(b).unwrap();
    vm.call(
        Call::builder(Arc::new(xor(data.len() * 8)))
            .arg(a)
            .arg(b)
            .build()
            .unwrap(),
    )
    .unwrap()
}

fn setup(vm: &mut dyn Vm<Binary>, key: [u8; 16], iv: [u8; 12], leader: bool) -> Aead {
    // In transport these references come from the joint key schedule. The
    // circuit test uses two private XOR shares, never public keys or IVs.
    let key = shared(vm, &key, leader).try_into().unwrap();
    let iv = shared(vm, &iv, leader).try_into().unwrap();
    Aead::alloc(vm, key, iv).unwrap()
}

#[test]
fn ghash_matches_nist_vector() {
    // Test the standard zero-key/zero-plaintext AES-GCM vector by adapting
    // its 16-byte plaintext into the TLS geometry with five-byte AAD.
    let key = [0; 16];
    let iv = [0; 12];
    for n in [1, 15, 16, 17, 33] {
        let content = vec![0xab; n];
        let header = record::aad(n + 16).unwrap();
        let encrypted = Aes128Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(
                (&iv).into(),
                Payload {
                    msg: &content,
                    aad: &header,
                },
            )
            .unwrap();
        // AES_0(0) and AES_0(0^96 || 1), from NIST's AES-GCM test vectors.
        let h: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let mask: [u8; 16] = [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
            0x45, 0x5a,
        ];
        let ct = encrypted[..n].to_vec();
        let hash: [u8; 16] = mpz_circuits::evaluate!(ghash(n), h, header, ct).unwrap();
        let tag: Vec<_> = hash.iter().zip(mask).map(|(&a, b)| a ^ b).collect();
        assert_eq!(&encrypted[n..], tag);
    }
}

#[tokio::test]
async fn garbled_tls13_records_match_reference_and_reject_tampering() {
    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);
    let (send, recv) = ideal_cot(delta.into_inner());
    let mut leader = Garbler::new(send, [0; 16], delta);
    let mut follower = Evaluator::new(recv);
    let (mut cx, mut cy) = test_st_context(8);
    let key = [17; 16];
    let iv = [37; 12];
    let inner = record::encode_inner(
        b"private HTTP response",
        record::ContentType::ApplicationData,
        7,
    )
    .unwrap();
    let header = record::aad(inner.len() + 16).unwrap();
    let mut wire = header.to_vec();
    wire.extend(
        Aes128Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(
                (&iv).into(),
                Payload {
                    msg: &inner,
                    aad: &header,
                },
            )
            .unwrap(),
    );

    async fn participant(
        vm: &mut (dyn Vm<Binary> + Send),
        ctx: &mut mpz_common::Context,
        key: [u8; 16],
        iv: [u8; 12],
        inner: &[u8],
        wire: &[u8],
        leader: bool,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut enc = setup(vm, key, iv, leader);
        let mut dec = setup(vm, key, iv, leader);
        let input = vm.alloc_vec(inner.len()).unwrap();
        if leader {
            vm.mark_private(input).unwrap();
            vm.assign(input, inner.to_vec()).unwrap();
        } else {
            vm.mark_blind(input).unwrap();
        }
        vm.commit(input).unwrap();
        let encrypted = enc.encrypt(vm, input).unwrap();
        let mut ct = vm.decode(encrypted.ciphertext).unwrap();
        let mut tag = vm.decode(encrypted.tag).unwrap();
        let pending = dec.decrypt(vm, wire).unwrap();
        let authenticated = pending.authenticate(vm, ctx).await.unwrap();
        // Plaintext decoding only happens after authenticating the record.
        let mut plaintext = vm.decode(authenticated).unwrap();
        vm.execute_all(ctx).await.unwrap();
        let mut result = encrypted.header.to_vec();
        result.extend(ct.try_recv().unwrap().unwrap());
        result.extend(tag.try_recv().unwrap().unwrap());
        let plaintext = plaintext.try_recv().unwrap().unwrap();
        // A second record has a distinct nonce. A modified tag must fail even
        // though the AES-CTR plaintext is otherwise valid.
        let header = record::aad(inner.len() + 16).unwrap();
        let mut bad = header.to_vec();
        bad.extend(
            Aes128Gcm::new_from_slice(&key)
                .unwrap()
                .encrypt(
                    (&record::nonce(iv, 1)).into(),
                    Payload {
                        msg: inner,
                        aad: &header,
                    },
                )
                .unwrap(),
        );
        *bad.last_mut().unwrap() ^= 1;
        let pending = dec.decrypt(vm, &bad).unwrap();
        assert!(pending.authenticate(vm, ctx).await.is_err());
        (result, plaintext)
    }
    let (a, b) = tokio::join!(
        participant(&mut leader, &mut cx, key, iv, &inner, &wire, true),
        participant(&mut follower, &mut cy, key, iv, &inner, &wire, false)
    );
    assert_eq!(a, b);
    assert_eq!(a.0, wire);
    assert_eq!(a.1, inner);
}
