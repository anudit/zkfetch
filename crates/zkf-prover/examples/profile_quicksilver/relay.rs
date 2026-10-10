//! Benchmark-only TCP shaping: delays every byte by half an RTT in each
//! direction, while preserving streaming/pipelining within a flight.
use anyhow::{Result, ensure};
use std::{
    sync::{
        Arc, Mutex,
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
    connections: AtomicU64,
    events: Mutex<Vec<Event>>,
    frames: Mutex<Vec<WebSocketFrame>>,
}
#[derive(Clone, serde::Serialize)]
pub struct Event {
    pub connection: u64,
    pub direction: &'static str,
    pub bytes: usize,
    pub micros: u64,
}
#[derive(Clone, serde::Serialize)]
pub struct WebSocketFrame {
    pub connection: u64,
    pub direction: &'static str,
    pub payload_bytes: u64,
    pub opcode: u8,
    pub fin: bool,
    pub micros: u64,
}

// Observe framing only. Payloads are skipped, never retained or exported.
#[derive(Default)]
struct FrameObserver {
    upgraded: bool,
    header: Vec<u8>,
    remaining: u64,
}
impl FrameObserver {
    fn feed(&mut self, mut bytes: &[u8], mut emit: impl FnMut(u64, u8, bool)) {
        while !bytes.is_empty() {
            if !self.upgraded {
                self.header.push(bytes[0]);
                bytes = &bytes[1..];
                assert!(
                    self.header.len() <= 16384,
                    "benchmark HTTP upgrade too large"
                );
                if self.header.ends_with(b"\r\n\r\n") {
                    self.upgraded = true;
                    self.header.clear();
                }
            } else if self.remaining > 0 {
                let n = self.remaining.min(bytes.len() as u64) as usize;
                self.remaining -= n as u64;
                bytes = &bytes[n..];
            } else {
                self.header.push(bytes[0]);
                bytes = &bytes[1..];
                if self.header.len() < 2 {
                    continue;
                }
                let tag = self.header[1] & 127;
                let extended = match tag {
                    126 => 2,
                    127 => 8,
                    _ => 0,
                };
                let header_len = 2 + extended + if self.header[1] & 128 != 0 { 4 } else { 0 };
                if self.header.len() != header_len {
                    continue;
                }
                let length = match tag {
                    126 => u16::from_be_bytes(self.header[2..4].try_into().unwrap()) as u64,
                    127 => u64::from_be_bytes(self.header[2..10].try_into().unwrap()),
                    n => n as u64,
                };
                emit(length, self.header[0] & 15, self.header[0] & 128 != 0);
                self.remaining = length;
                self.header.clear();
            }
        }
    }
}
impl Counters {
    pub fn frames(&self) -> Vec<WebSocketFrame> {
        self.frames.lock().unwrap().clone()
    }
    pub fn trace(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
    pub fn snapshot(&self) -> [u64; 3] {
        [
            self.sent.load(Relaxed),
            self.received.load(Relaxed),
            self.changes.load(Relaxed),
        ]
    }
    fn record(&self, up: bool, n: usize, direction: &AtomicU8, connection: u64, epoch: Instant) {
        if up { &self.sent } else { &self.received }.fetch_add(n as u64, Relaxed);
        self.events.lock().unwrap().push(Event {
            connection,
            direction: if up { "up" } else { "down" },
            bytes: n,
            micros: epoch.elapsed().as_micros() as u64,
        });
        let dir = if up { 1 } else { 2 };
        let previous = direction.swap(dir, Relaxed);
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
            let connection = counters.connections.fetch_add(1, Relaxed);
            tokio::spawn(async move {
                let b = TcpStream::connect(target).await?;
                a.set_nodelay(true)?;
                b.set_nodelay(true)?;
                let (ar, aw) = tokio::io::split(a);
                let (br, bw) = tokio::io::split(b);
                let delay = Duration::from_micros(rtt_ms * 500);
                let direction = Arc::new(AtomicU8::new(0));
                let epoch = Instant::now();
                tokio::try_join!(
                    pipe(
                        ar,
                        bw,
                        delay,
                        counters.clone(),
                        true,
                        direction.clone(),
                        connection,
                        epoch
                    ),
                    pipe(br, aw, delay, counters, false, direction, connection, epoch)
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
    direction: Arc<AtomicU8>,
    connection: u64,
    epoch: Instant,
) -> std::io::Result<()> {
    let (tx, mut rx) = mpsc::channel::<(Instant, Vec<u8>)>(64);
    let read = async move {
        let mut observer = FrameObserver::default();
        loop {
            let mut buf = vec![0; 65536];
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            buf.truncate(n);
            counters.record(up, n, &direction, connection, epoch);
            observer.feed(&buf, |payload_bytes, opcode, fin| {
                counters.frames.lock().unwrap().push(WebSocketFrame {
                    connection,
                    direction: if up { "up" } else { "down" },
                    payload_bytes,
                    opcode,
                    fin,
                    micros: epoch.elapsed().as_micros() as u64,
                });
            });
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observes_fragmented_headers_and_coalesced_frames_without_payloads() {
        let mut observer = FrameObserver::default();
        let mut frames = Vec::new();
        let mut wire = b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec();
        // Masked binary, extended 16-bit length, and then an empty close frame.
        wire.extend([0x82, 0xfe, 0, 130, 1, 2, 3, 4]);
        wire.extend([0; 130]);
        wire.extend([0x88, 0]);
        for byte in &wire {
            observer.feed(&[*byte], |n, op, fin| frames.push((n, op, fin)));
        }
        assert_eq!(frames, [(130, 2, true), (0, 8, true)]);
        assert!(observer.header.is_empty());
        assert_eq!(observer.remaining, 0);
        observer.feed(&[0x82, 1, 42, 0x82, 0], |n, op, fin| {
            frames.push((n, op, fin))
        });
        assert_eq!(&frames[2..], [(1, 2, true), (0, 2, true)]);
    }
}
