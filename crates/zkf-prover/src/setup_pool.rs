use anyhow::Result;
use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::Duration,
};
use tlsn::vole_pool::ProverVolePool;
use web_time::Instant;
use zkf_core::{notary_auth, setup_pool::PoolRequest, transport};

struct Cached {
    request: PoolRequest,
    pool: ProverVolePool,
    inserted: Instant,
}
static POOLS: LazyLock<Mutex<HashMap<String, Cached>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
// Keys include the complete endpoint (and its admission capability), pin and
// protocol version. Only a successful session can return a lease to the cache.
pub(crate) struct ClientLease {
    key: String,
    request: PoolRequest,
    pub(crate) pool: ProverVolePool,
    pub(crate) resumed: bool,
    pub(crate) low_latency: bool,
    pub(crate) prefill_check: Vec<u8>,
}
impl ClientLease {
    pub(crate) fn finish(mut self) {
        if self.pool.park().is_err() {
            return;
        }
        let Some(generation) = self.request.generation.checked_add(1) else {
            return;
        };
        let mut cache = POOLS.lock().unwrap();
        cache.retain(|_, e| e.inserted.elapsed() < Duration::from_secs(600));
        if cache.len() >= 4 {
            if let Some(key) = cache
                .iter()
                .min_by_key(|(_, e)| e.inserted)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&key);
            }
        }
        cache.insert(
            self.key,
            Cached {
                request: PoolRequest {
                    generation,
                    ..self.request
                },
                pool: self.pool,
                inserted: Instant::now(),
            },
        );
    }
}
pub(crate) async fn open(
    stream: &mut transport::ClientStream,
    key: String,
    pin: Option<&str>,
    proxy_open: Option<notary_auth::ProxyOpen>,
    low_latency: bool,
    budget: usize,
    strict_authentication: bool,
) -> Result<Option<ClientLease>> {
    use rand::RngCore;
    let mut cached = {
        let mut cache = POOLS.lock().unwrap();
        cache.retain(|_, e| e.inserted.elapsed() < Duration::from_secs(600));
        cache.remove(&key)
    };
    let request = match &cached {
        Some(c) => c.request,
        None => {
            let mut device = [0; 32];
            rand::rngs::OsRng.fill_bytes(&mut device);
            PoolRequest {
                device,
                ..Default::default()
            }
        }
    };
    let opening = if low_latency {
        if let Some(c) = cached.as_mut() {
            c.pool.set_budget(budget).map_err(anyhow::Error::msg)?;
        }
        let ferret = match cached.as_mut() {
            Some(c) => c.pool.start_prefill().map_err(anyhow::Error::msg)?,
            None => vec![],
        };
        notary_auth::authenticate_pool_setup(
            stream,
            pin,
            request,
            notary_auth::SetupOpen {
                authentication_lanes: if strict_authentication { 2 } else { 1 },
                // Cold bootstrap completes before forwarding the first TLS flight.
                proxy: if cached.is_some() { proxy_open } else { None },
                budget: budget as u32,
                ferret,
            },
        )
        .await?
    } else {
        notary_auth::authenticate_pool(stream, pin, request).await?
    };
    let Some(opening) = opening else {
        anyhow::ensure!(
            !strict_authentication,
            "strict authentication cannot fall back to a legacy opening"
        );
        return Ok(None);
    };
    anyhow::ensure!(
        !strict_authentication
            || opening
                .setup
                .as_ref()
                .is_some_and(|s| s.authentication_lanes == 2),
        "strict session requires authenticated dual-lane setup"
    );
    let mut pool = if opening.resumed {
        cached
            .ok_or_else(|| anyhow::anyhow!("notary resumed an unknown VOLE pool"))?
            .pool
    } else {
        {
            let mut pool = ProverVolePool::new(opening.binding);
            if strict_authentication {
                pool.enable_strict_authentication()
                    .map_err(anyhow::Error::msg)?;
            }
            pool
        }
    };
    anyhow::ensure!(
        pool.is_strict_authentication() == strict_authentication,
        "cached pool authentication mode mismatch"
    );
    pool.set_budget(budget).map_err(anyhow::Error::msg)?;
    let prefill_check = if opening.low_latency && opening.resumed {
        pool.prefill_check(&opening.ferret_reply)
            .map_err(anyhow::Error::msg)?
    } else {
        vec![]
    };
    pool.bind(opening.binding);
    pool.set_low_latency(opening.low_latency);
    pool.set_pipeline_tls(opening.proxy_open.is_some());
    pool.set_opened_host(if opening.resumed {
        opening.proxy_open.as_ref().map(|o| o.host.clone())
    } else {
        None
    });
    Ok(Some(ClientLease {
        key,
        request: opening.request,
        pool,
        resumed: opening.resumed,
        low_latency: opening.low_latency,
        prefill_check,
    }))
}
