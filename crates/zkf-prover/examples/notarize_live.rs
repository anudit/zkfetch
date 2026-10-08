//! Notarizes a live URL: `notarize_live <notary-ws-url> <https-url> [1.2|1.3|auto] [mpc|proxy]`.
//! Set `RUST_LOG` (e.g. `tlsn=trace`) for protocol tracing.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [notary_url, url, rest @ ..] = args.as_slice() else {
        anyhow::bail!(
            "usage: notarize_live <notary-ws-url> <https-url> [1.2|1.3|auto] [mpc|proxy]"
        );
    };
    let params = serde_json::from_value::<zkf_core::NotarizeParams>(serde_json::json!({
        "notaryUrl": notary_url,
        "url": url,
        "tlsVersion": rest.first().map(String::as_str).unwrap_or("auto"),
        "mode": rest.get(1).map(String::as_str).unwrap_or("mpc"),
    }))?;
    let out = zkf_prover::notarize(params).await?;
    println!("ok: status {} in {:?}", out.response.status, out.timings);
    println!(
        "{}",
        out.response.body.chars().take(300).collect::<String>()
    );
    Ok(())
}
