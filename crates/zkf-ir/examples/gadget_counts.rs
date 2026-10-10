//! Run with `cargo run --release -p zkf-ir --example gadget_counts`.
use zkf_ir::{
    Circuit,
    aes::ExpandedKey,
    tls::{counter_block, ctr_block, key_commitment},
};

fn main() {
    println!("{{\"reference_only\":true,\"proof_backend_implemented\":false,\"gadgets\":[");
    for (i, key_bytes) in [16, 32].into_iter().enumerate() {
        let mut c = Circuit::default();
        let refs: Vec<_> = (0..key_bytes).map(|_| c.commit_byte()).collect();
        let key = ExpandedKey::new(&mut c, &refs).unwrap();
        let expansion = c.committed_bits();
        key_commitment(&mut c, &key);
        let commitment = c.committed_bits();
        ctr_block(
            &mut c,
            &key,
            counter_block([0; 12], 0, 0).unwrap(),
            [0; 16],
            [None; 16],
        )
        .unwrap();
        let block = c.committed_bits() - commitment;
        println!(
            "{}{{\"aes_bits\":{},\"key_and_expansion_committed_bits\":{},\"key_commitment_total_bits\":{},\"ctr_block_increment_bits\":{},\"constraints_after_one_ctr_block\":{},\"edges_after_one_ctr_block\":{}}}",
            if i == 0 { "" } else { "," },
            key_bytes * 8,
            expansion,
            commitment,
            block,
            c.constraint_count(),
            c.edge_count()
        );
    }
    println!("]}}");
}
