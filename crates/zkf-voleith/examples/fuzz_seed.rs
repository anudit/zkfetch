//! Generate a proof of a public, synthetic bit for the decoder fuzz corpus.
use zkf_ir::{Circuit, Term, field::Fe};
use zkf_voleith::{
    experimental::{self, Context},
    primitives::Parameters,
};
fn main() -> anyhow::Result<()> {
    let directory = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: fuzz_seed <corpus directory>"))?;
    std::fs::create_dir_all(&directory)?;
    let mut c = Circuit::default();
    let x = c.commit_bit();
    c.assert_zero(vec![Term::Linear(Fe::ONE, x), Term::Constant(Fe::ONE)]);
    let witness = c.eval(&[Fe::ONE])?;
    let context = Context {
        attestation_digest: [1; 32],
        statement: b"public fuzz seed relation",
        presentation_nonce: [2; 32],
    };
    for (name, param) in [("fast", Parameters::Fast), ("small", Parameters::Small)] {
        let proof = experimental::prove(&c, &witness, param, &context)?;
        experimental::verify(&c, &proof, &context)?;
        std::fs::write(std::path::Path::new(&directory).join(name), proof)?;
    }
    Ok(())
}
