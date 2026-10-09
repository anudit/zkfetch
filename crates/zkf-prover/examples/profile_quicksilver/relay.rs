//! Benchmark-only TCP shaping: delays every byte by half an RTT in each
//! direction, while preserving streaming/pipelining within a flight.
use anyhow::{Result, ensure};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::{Instant, sleep_until},
};

#[derive(Default)]
pub struct Counters {
    sent: AtomicU64,
    received: AtomicU64,
    changes: AtomicU64,
    direction: AtomicU8,
}
impl Counters {
    pub fn snapshot(&self) -> [u64; 3] {
        [
            self.sent.load(Relaxed),
            self.received.load(Relaxed),
            self.changes.load(Relaxed),
        ]
    }
    fn record(&self, up: bool, n: usize) {
        if up { &self.sent } else { &self.received }.fetch_add(n as u64, Relaxed);
        let dir = if up { 1 } else { 2 };
        let previous = self.direction.swap(dir, Relaxed);
        if previous != 0 && previous != dir {
            self.changes.fetch_add(1, Relaxed);
        }
    }
}
pub async fn start(url: &str, rtt_ms: u64) -> Result<(String, Arc<Counters>)> {
    let url = url::Url::parse(url)?;
    ensure!(
        url.scheme() == "ws",
        "RTT shaping requires a local ws:// endpoint"
    );
    let host = url.host_str().unwrap();
    ensure!(
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()),
        "RTT shaping is loopback-only"
    );
    let target = format!("{}:{}", host, url.port_or_known_default().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut endpoint = url.clone();
    endpoint.set_host(Some("127.0.0.1"))?;
    endpoint
        .set_port(Some(listener.local_addr()?.port()))
        .unwrap();
    let counters = Arc::new(Counters::default());
    let metrics = counters.clone();
    tokio::spawn(async move {
        while let Ok((a, _)) = listener.accept().await {
            let target = target.clone();
            let counters = metrics.clone();
            tokio::spawn(async move {
                let b = TcpStream::connect(target).await?;
                a.set_nodelay(true)?;
                b.set_nodelay(true)?;
                let (ar, aw) = tokio::io::split(a);
                let (br, bw) = tokio::io::split(b);
                let delay = Duration::from_micros(rtt_ms * 500);
                tokio::try_join!(
                    pipe(ar, bw, delay, counters.clone(), true),
                    pipe(br, aw, delay, counters, false)
                )?;
                Ok::<_, std::io::Error>(())
            });
        }
    });
    Ok((endpoint.to_string(), counters))
}
async fn pipe(
    mut reader: ReadHalf<TcpStream>,
    mut writer: WriteHalf<TcpStream>,
    delay: Duration,
    counters: Arc<Counters>,
    up: bool,
) -> std::io::Result<()> {
    let (tx, mut rx) = mpsc::channel::<(Instant, Vec<u8>)>(64);
    let read = async move {
        loop {
            let mut buf = vec![0; 65536];
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            buf.truncate(n);
            counters.record(up, n);
            if tx.send((Instant::now() + delay, buf)).await.is_err() {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    };
    let write = async move {
        while let Some((deadline, bytes)) = rx.recv().await {
            sleep_until(deadline).await;
            writer.write_all(&bytes).await?;
        }
        writer.shutdown().await
    };
    tokio::try_join!(read, write)?;
    Ok(())
}
