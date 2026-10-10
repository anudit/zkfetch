//! Degree-three bridge borrowing both authentication lanes of the strict VM.
//! All lanes bind the same public relation; masking correlations are consumed
//! once and no independently assigned copy replaces a borrowed TLS key.
use super::{binding, field_rows, layout, lift_rows, pack, Weights};
use crate::{backend::check::Polynomial, field::Fe, Circuit, Witness};
use anyhow::{ensure, Result};
use mpz_common::{Context, Flush};
use mpz_core::Block;
use mpz_ot::rcot::{RCOTReceiver, RCOTSender};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        MemoryExt, Repr, ViewExt,
    },
    Execute,
};
use mpz_zk::strict::{Prover, Verifier};
use rand::RngCore;
use serio::{stream::IoStreamExt, SinkExt};
use zeroize::Zeroizing;
fn lane_binding(binding: &[u8], lane: usize) -> Vec<u8> {
    let mut b = b"zkf/strict/degree-three/two-independent-lanes/v1\0".to_vec();
    b.extend_from_slice(&(lane as u64).to_le_bytes());
    b.extend_from_slice(binding);
    b
}
pub async fn prove_prefixes<OT, R>(
    vm: &mut Prover<OT>,
    ctx: &mut Context,
    c: &Circuit,
    witness: &Witness,
    prefixes: &[R],
    statement: &[u8],
) -> Result<()>
where
    OT: RCOTReceiver<bool, Block> + Flush + Send + 'static,
    R: Repr<Binary> + Copy,
{
    let checked = c.checked(witness)?;
    let prefix_bits = prefixes.iter().map(|p| p.to_raw().len()).sum();
    let bytes = layout(c, prefix_bits)?;
    let mut values = pack(c, &checked)?;
    let mut masks = Zeroizing::new([0u8; 64]);
    rand::rngs::OsRng.fill_bytes(masks.as_mut());
    values.extend_from_slice(masks.as_ref());
    let extra = vm.alloc_vec::<U8>(values.len() - prefix_bits / 8)?;
    vm.mark_private(extra)?;
    vm.assign(extra, values[prefix_bits / 8..].to_vec())?;
    vm.commit(extra)?;
    let bound = lane_binding(&binding(c, statement, c.profile().is_some()), 2);
    vm.bind_statement(&bound);
    vm.flush(ctx).await?;
    let macs: Vec<_> = prefixes
        .iter()
        .map(|p| vm.get_macs(*p))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .chain(vm.get_macs(extra)?)
        .copied()
        .collect();
    ensure!(
        macs.len() == (bytes + 64) * 8,
        "wrong dual authentication row count"
    );
    let seed = vm.field_challenge();
    let mut message = [[[0u8; 16]; 3]; 2];
    for lane in 0..2 {
        let rows = Zeroizing::new(
            macs.iter()
                .map(|m| Fe(u128::from_le_bytes(m.tags()[lane].to_bytes())))
                .collect::<Vec<_>>(),
        );
        let tags = lift_rows(c, &rows);
        let mut weights = Weights::new(&seed, &lane_binding(&bound, lane));
        let mut coeff = Zeroizing::new([Fe::ZERO; 3]);
        if c.edge_count() >= 32_768 {
            let weights: Vec<_> = (0..c.constraint_count()).map(|_| weights.next()).collect();
            let plan = c.streaming_plan(&[])?;
            let mut valid = true;
            plan.prover_constraints(&checked, &tags, |i, p| {
                valid &= p.0[3] == Fe::ZERO;
                for j in 0..3 {
                    coeff[j] = coeff[j] ^ (weights[i] * p.0[j]);
                }
            })?;
            ensure!(valid, "unsatisfied dual relation");
        } else {
            let polys = c.constraint_polynomials_checked(&checked, &tags)?;
            for p in &polys.0 {
                ensure!(p.0[3] == Fe::ZERO, "unsatisfied dual relation");
                let chi = weights.next();
                for j in 0..3 {
                    coeff[j] = coeff[j] ^ (chi * p.0[j]);
                }
            }
        }
        let at = bytes * 8 + lane * 256;
        let mask_at = lane * 32;
        coeff[0] = coeff[0] ^ field_rows(&rows[at..at + 128]);
        coeff[1] = coeff[1]
            ^ Fe(u128::from_le_bytes(
                masks[mask_at..mask_at + 16].try_into()?,
            ))
            ^ field_rows(&rows[at + 128..at + 256]);
        coeff[2] = coeff[2]
            ^ Fe(u128::from_le_bytes(
                masks[mask_at + 16..mask_at + 32].try_into()?,
            ));
        message[lane] = coeff.map(|v| v.0.to_le_bytes());
    }
    ctx.io_mut().send(message).await?;
    vm.bind_statement(&message.concat().concat());
    Ok(())
}
pub async fn verify_prefixes<OT, R>(
    vm: &mut Verifier<OT>,
    ctx: &mut Context,
    c: &Circuit,
    prefixes: &[R],
    statement: &[u8],
) -> Result<()>
where
    OT: RCOTSender<Block> + Flush + Send + 'static,
    R: Repr<Binary> + Copy,
{
    let prefix_bits = prefixes.iter().map(|p| p.to_raw().len()).sum();
    let bytes = layout(c, prefix_bits)?;
    let extra = vm.alloc_vec::<U8>(bytes + 64 - prefix_bits / 8)?;
    vm.mark_blind(extra)?;
    vm.commit(extra)?;
    let bound = lane_binding(&binding(c, statement, c.profile().is_some()), 2);
    vm.bind_statement(&bound);
    vm.flush(ctx).await?;
    let keys: Vec<_> = prefixes
        .iter()
        .map(|p| vm.get_keys(*p))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .chain(vm.get_keys(extra)?)
        .copied()
        .collect();
    ensure!(
        keys.len() == (bytes + 64) * 8,
        "wrong dual authentication row count"
    );
    let seed = vm.field_challenge();
    let mut expected = [Fe::ZERO; 2];
    for lane in 0..2 {
        let rows = Zeroizing::new(
            keys.iter()
                .map(|k| Fe(u128::from_le_bytes(k.tags()[lane].to_bytes())))
                .collect::<Vec<_>>(),
        );
        let commitments = lift_rows(c, &rows);
        let delta = Fe(u128::from_le_bytes(vm.deltas()[lane].as_block().to_bytes()));
        let at = bytes * 8 + lane * 256;
        expected[lane] =
            field_rows(&rows[at..at + 128]) ^ (delta * field_rows(&rows[at + 128..at + 256]));
        let mut weights = Weights::new(&seed, &lane_binding(&bound, lane));
        let checks = Zeroizing::new(c.verifier_constraints(&commitments, delta)?);
        for check in checks.iter() {
            expected[lane] = expected[lane] ^ (weights.next() * *check);
        }
    }
    let message: [[[u8; 16]; 3]; 2] = ctx.io_mut().expect_next().await?;
    let mut valid = true;
    for lane in 0..2 {
        let delta = Fe(u128::from_le_bytes(vm.deltas()[lane].as_block().to_bytes()));
        let p = Polynomial([
            Fe(u128::from_le_bytes(message[lane][0])),
            Fe(u128::from_le_bytes(message[lane][1])),
            Fe(u128::from_le_bytes(message[lane][2])),
            Fe::ZERO,
        ]);
        valid &= p.at(delta) == expected[lane];
    }
    ensure!(valid, "strict degree-three check rejected");
    vm.bind_statement(&message.concat().concat());
    Ok(())
}
