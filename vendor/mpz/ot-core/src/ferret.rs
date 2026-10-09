//! An implementation of the [`Ferret`](https://eprint.iacr.org/2020/924.pdf) protocol.

mod config;
pub(crate) mod cuckoo;
pub(crate) mod mpcot;
mod receiver;
mod sender;
pub(crate) mod spcot;

pub use config::{
    FerretConfig, FerretConfigBuilder, FerretConfigBuilderError, REGULAR_PARAMS, UNIFORM_PARAMS,
};
pub use receiver::{Receiver, ReceiverError};
pub use sender::{Sender, SenderError};

use blake3::Hash;
use mpz_core::Block;
use serde::{Deserialize, Serialize};

use crate::Derandomize;

/// Initialize message sent from receiver to sender.
#[derive(Debug, Serialize, Deserialize)]
pub struct Init {
    seed: Block,
}

/// Extend message sent from sender to receiver.
#[derive(Debug, Serialize, Deserialize)]
pub struct SenderExtend {
    ms: Vec<[Block; 2]>,
    sums: Vec<Block>,
}

/// Check message sent from sender to receiver.
#[derive(Debug, Serialize, Deserialize)]
pub struct SenderCheck {
    hashed_v: Hash,
}

/// Extend message sent from receiver to sender.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiverExtend {
    derandomize: Derandomize,
}

/// Check message sent from receiver to sender.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiverCheck {
    derandomize: Derandomize,
}

// Wipe consumed bootstrap/output material before shortening the retained pool.
fn truncate_secret<T: zeroize::Zeroize>(values: &mut Vec<T>, len: usize) {
    for value in &mut values[len..] {
        value.zeroize();
    }
    values.truncate(len);
}
fn take_tail<T: Copy + zeroize::Zeroize>(values: &mut Vec<T>, count: usize) -> Vec<T> {
    let len = values.len() - count;
    let out = values[len..].to_vec();
    truncate_secret(values, len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ferret::config::TEST_PARAMS,
        ideal::rcot::IdealRCOT,
        rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
        test::assert_cot,
    };
    use mpz_core::lpn::LpnType;
    use rand::{SeedableRng, rngs::StdRng};
    use rstest::*;

    #[test]
    fn buffered_allocations_do_not_accumulate_across_sessions() {
        use rand::Rng;
        let mut rng = StdRng::seed_from_u64(2);
        let delta = rng.random();
        let cot = IdealRCOT::new(rng.random(), delta);
        let config = FerretConfig::builder()
            .lpn_type(LpnType::Regular)
            .build()
            .unwrap();
        let mut sender = Sender::new(rng.random(), config.clone(), cot.clone());
        let mut receiver = Receiver::new(rng.random(), config, cot);
        sender.initialize(receiver.initialize().unwrap()).unwrap();
        sender.alloc_bootstrap().unwrap();
        receiver.alloc_bootstrap().unwrap();
        sender.acquire_cot().flush().unwrap();
        receiver.acquire_cot().flush().unwrap();
        sender.alloc(100).unwrap();
        receiver.alloc(100).unwrap();
        while sender.wants_extend() {
            sender.start_extend().unwrap();
            let msg = sender.extend(receiver.start_extend().unwrap()).unwrap();
            let msg = receiver.extend(msg).unwrap();
            receiver.finish_extend(sender.check(msg).unwrap()).unwrap();
            sender.finish_extend().unwrap();
        }
        for _ in 0..100 {
            sender.alloc(100).unwrap();
            receiver.alloc(100).unwrap();
            assert!(!sender.wants_extend() && !receiver.wants_extend());
            let keys = sender.try_send_rcot(100).unwrap();
            let out = receiver.try_recv_rcot(100).unwrap();
            assert_cot(delta, &out.choices, &keys.keys, &out.msgs);
        }
        // Outstanding allocation is zero. Asking for all remaining buffered
        // output must not trigger an extension for already consumed requests.
        let n = sender.available();
        assert_eq!(n, receiver.available());
        sender.alloc(n).unwrap();
        receiver.alloc(n).unwrap();
        assert!(!sender.wants_extend() && !receiver.wants_extend());
        sender.try_send_rcot(n).unwrap();
        receiver.try_recv_rcot(n).unwrap();
        assert!(!sender.wants_bootstrap() && !receiver.wants_bootstrap());
    }

    #[rstest]
    #[case::uniform(LpnType::Uniform)]
    #[case::regular(LpnType::Regular)]
    fn test_ferret(#[case] lpn_type: LpnType) {
        use rand::Rng;

        let mut rng = StdRng::seed_from_u64(0);
        let delta = rng.random();
        let cot = IdealRCOT::new(rng.random(), delta);

        let mut builder = FerretConfig::builder();

        builder.lpn_type(lpn_type);
        builder.param_selector(|_, _, _| TEST_PARAMS);

        let config = builder.build().unwrap();
        let count = TEST_PARAMS.n * 2;

        let mut sender = Sender::new(rng.random(), config.clone(), cot.clone());
        let mut receiver = Receiver::new(rng.random(), config, cot);

        assert!(sender.wants_init());
        assert!(receiver.wants_init());

        let init = receiver.initialize().unwrap();
        sender.initialize(init).unwrap();

        assert!(!sender.wants_init());
        assert!(!receiver.wants_init());

        assert!(sender.wants_bootstrap());
        assert!(receiver.wants_bootstrap());

        sender.alloc_bootstrap().unwrap();
        receiver.alloc_bootstrap().unwrap();

        sender.acquire_cot().flush().unwrap();
        receiver.acquire_cot().flush().unwrap();

        sender.alloc(count).unwrap();
        receiver.alloc(count).unwrap();

        while sender.wants_extend() && receiver.wants_extend() {
            sender.start_extend().unwrap();
            let msg = receiver.start_extend().unwrap();
            let msg = sender.extend(msg).unwrap();
            let msg = receiver.extend(msg).unwrap();
            let msg = sender.check(msg).unwrap();
            receiver.finish_extend(msg).unwrap();
            sender.finish_extend().unwrap();
        }

        assert!(!sender.wants_extend());
        assert!(!receiver.wants_extend());

        let RCOTSenderOutput { keys, .. } = sender.try_send_rcot(count).unwrap();
        let RCOTReceiverOutput { choices, msgs, .. } = receiver.try_recv_rcot(count).unwrap();

        assert_cot(delta, &choices, &keys, &msgs);
    }
}
