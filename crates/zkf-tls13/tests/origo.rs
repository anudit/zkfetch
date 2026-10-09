use hmac::{Hmac, Mac};
use mpz_common::context::test_st_context;
use mpz_ideal_vm::IdealVm;
use mpz_vm_core::{Execute, memory::MemoryExt};
use sha2::{Digest, Sha256};
use zkf_tls13_schedule::{OrigoClaim, OrigoSchedule};
fn mac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut h = Hmac::<Sha256>::new_from_slice(key).unwrap();
    h.update(msg);
    h.finalize().into_bytes().into()
}
fn expand(key: &[u8], label: &[u8], ctx: &[u8], len: usize) -> Vec<u8> {
    let mut m = (len as u16).to_be_bytes().to_vec();
    m.push((6 + label.len()) as u8);
    m.extend(b"tls13 ");
    m.extend(label);
    m.push(ctx.len() as u8);
    m.extend(ctx);
    m.push(1);
    mac(key, &m)[..len].to_vec()
}
async fn run(tamper: Option<usize>, bad_witness: bool) {
    let secret = [42; 32];
    let hello = [3; 32];
    let handshake = [7; 32];
    let (mut claim, mut witness) = OrigoClaim::preprocess(&secret, hello, handshake);
    // Bincode has fixed arrays: HS outer, client/server handshake inner, then
    // dHS/MS/client/server inner pad states. Change each disclosed pad.
    if let Some(offset) = tamper {
        let mut bytes = bincode::serialize(&claim).unwrap();
        bytes[offset] ^= 1;
        claim = bincode::deserialize(&bytes).unwrap();
    }
    if bad_witness {
        witness[0] ^= 1;
    }
    let (mut a, mut b) = (IdealVm::new(), IdealVm::new());
    let (mut ca, mut cb) = test_st_context(8);
    let mut pa = OrigoSchedule::alloc(&mut a, true).unwrap();
    let mut pb = OrigoSchedule::alloc(&mut b, false).unwrap();
    pa.assign(&mut a, &claim, handshake, Some(witness)).unwrap();
    pb.assign(&mut b, &claim, handshake, None).unwrap();
    let mut ck = a.decode(pa.keys.client_write_key).unwrap();
    let mut sk = a.decode(pa.keys.server_write_key).unwrap();
    let mut ci = a.decode(pa.keys.client_iv).unwrap();
    let mut si = a.decode(pa.keys.server_iv).unwrap();
    let _bk = b.decode(pb.keys.client_write_key).unwrap();
    let _sk = b.decode(pb.keys.server_write_key).unwrap();
    let _ci = b.decode(pb.keys.client_iv).unwrap();
    let _si = b.decode(pb.keys.server_iv).unwrap();
    futures::try_join!(a.execute_all(&mut ca), b.execute_all(&mut cb)).unwrap();
    if tamper.is_some() || bad_witness {
        assert!(pa.verify(&claim).is_err());
        assert!(pb.verify(&claim).is_err());
        return;
    }
    pa.verify(&claim).unwrap();
    pb.verify(&claim).unwrap();
    let early = mac(&[0; 32], &[0; 32]);
    let empty: [u8; 32] = Sha256::digest([]).into();
    let salt = expand(&early, b"derived", &empty, 32);
    let hs = mac(&salt, &secret);
    let (ch, sh) = claim.handshake_secrets();
    assert_eq!(ch.as_slice(), expand(&hs, b"c hs traffic", &hello, 32));
    assert_eq!(sh.as_slice(), expand(&hs, b"s hs traffic", &hello, 32));
    let derived = expand(&hs, b"derived", &empty, 32);
    let master = mac(&derived, &[0; 32]);
    let c = expand(&master, b"c ap traffic", &handshake, 32);
    let s = expand(&master, b"s ap traffic", &handshake, 32);
    assert_eq!(
        ck.try_recv().unwrap().unwrap().as_slice(),
        expand(&c, b"key", &[], 16)
    );
    assert_eq!(
        sk.try_recv().unwrap().unwrap().as_slice(),
        expand(&s, b"key", &[], 16)
    );
    assert_eq!(
        ci.try_recv().unwrap().unwrap().as_slice(),
        expand(&c, b"iv", &[], 12)
    );
    assert_eq!(
        si.try_recv().unwrap().unwrap().as_slice(),
        expand(&s, b"iv", &[], 12)
    );
}
#[tokio::test]
async fn keys_and_ivs_match_full_schedule() {
    run(None, false).await;
}
#[tokio::test]
async fn altered_states_and_witness_are_rejected() {
    for offset in [0, 96, 128, 160, 192] {
        run(Some(offset), false).await;
    }
    run(None, true).await;
}
