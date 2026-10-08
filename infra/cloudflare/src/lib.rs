use worker::*;

// Keep TLS termination/routing in a Rust Wasm Worker. The MPC verifier runs
// in a native Rust container, with its own threads and hardware instructions.
#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let path = req.path();
    if path != "/notarize" && path != "/health" {
        return Response::error("Not found", 404);
    }
    if req.method() != Method::Get {
        return Response::error("Method not allowed", 405);
    }
    if path == "/notarize"
        && req.headers().get("Upgrade")?.as_deref().map(str::to_ascii_lowercase).as_deref()
            != Some("websocket")
    {
        return Response::error("WebSocket upgrade required", 426);
    }
    let namespace = env.durable_object("NOTARY")?;
    let id = namespace.id_from_name("notary-v1")?;
    let hint = env.var("LOCATION_HINT")?.to_string();
    let stub = id.get_stub_with_location_hint(&hint)?;
    let colo = req.cf().map(|cf| cf.colo()).unwrap_or_default();
    let mut response = stub.fetch_with_request(req).await?;
    if path == "/health" {
        response = response.cloned()?;
        response.headers_mut().set("x-zkf-worker-colo", &colo)?;
    }
    Ok(response)
}
