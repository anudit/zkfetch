use anyhow::{Result, anyhow, ensure};
use tlsn::{rangeset::set::RangeSet, transcript::PartialTranscript};
use zkf_core::VerifyOptions;

fn authenticated(ranges: &RangeSet<usize>, start: usize, end: usize) -> bool {
    use tlsn::rangeset::ops::Set;
    RangeSet::from(start..end).is_subset(ranges)
}

fn head<'a>(
    bytes: &'a [u8],
    authed: &RangeSet<usize>,
) -> Result<(&'a str, Vec<(&'a str, &'a str)>, usize)> {
    let end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("HTTP head is unavailable"))?
        + 4;
    let text = std::str::from_utf8(&bytes[..end])?;
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap();
    ensure!(
        authenticated(authed, 0, first.len() + 2),
        "HTTP start line is not authenticated"
    );
    let mut headers = Vec::new();
    let mut offset = first.len() + 2;
    for line in lines.take_while(|l| !l.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid HTTP header"))?;
        ensure!(
            authenticated(authed, offset, offset + name.len() + 1),
            "HTTP header name is not authenticated"
        );
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            ensure!(
                authenticated(authed, offset, offset + line.len() + 2),
                "HTTP framing header is not authenticated"
            );
        }
        // Only authenticated headers can influence policy.
        if authenticated(authed, offset, offset + line.len() + 2) {
            headers.push((name, value.trim()));
        }
        offset += line.len() + 2;
    }
    Ok((first, headers, end))
}

fn unique<'a>(headers: &[(&'a str, &'a str)], name: &str) -> Result<Option<&'a str>> {
    let mut values = headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name));
    let value = values.next().map(|(_, v)| *v);
    ensure!(values.next().is_none(), "duplicate policy header: {name}");
    Ok(value)
}

pub(super) fn check(
    t: &PartialTranscript,
    server: &str,
    time: u64,
    opts: &VerifyOptions,
) -> Result<()> {
    if let Some(expected) = &opts.expected_server_name {
        ensure!(
            expected.eq_ignore_ascii_case(server),
            "server name mismatch"
        );
    }
    if let Some(max_age) = opts.max_age_secs {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        ensure!(time <= now, "attestation timestamp is in the future");
        ensure!(now - time <= max_age, "attestation is stale");
    }
    // Every presentation must bind the HTTP authority to the certificate identity.
    // The request target may be hidden; its policy is checked only when requested.
    let bytes = t.sent_unsafe();
    let end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("request head unavailable"))?
        + 4;
    let text = std::str::from_utf8(&bytes[..end])?;
    let mut offset = 0;
    let mut hosts = Vec::new();
    for line in text.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            ensure!(
                authenticated(t.sent_authed(), offset, offset + name.len() + 1),
                "request header name is not authenticated"
            );
            if name.eq_ignore_ascii_case("host") {
                ensure!(
                    authenticated(t.sent_authed(), offset, offset + line.len() + 2),
                    "HTTP Host is not authenticated"
                );
                hosts.push(value.trim());
            }
        }
        offset += line.len() + 2;
    }
    ensure!(
        hosts.len() == 1,
        "HTTP request must contain one authenticated Host"
    );
    let host = hosts[0].strip_suffix(":443").unwrap_or(hosts[0]);
    ensure!(
        host.eq_ignore_ascii_case(server),
        "HTTP Host does not match the attested server"
    );
    if opts.expected_method.is_some() || opts.expected_target.is_some() {
        let (line, _, _) = head(bytes, t.sent_authed())?;
        let parts: Vec<_> = line.split(' ').collect();
        ensure!(
            parts.len() == 3 && parts[2] == "HTTP/1.1",
            "invalid HTTP request line"
        );
        if let Some(method) = &opts.expected_method {
            ensure!(parts[0] == method, "HTTP method mismatch");
        }
        if let Some(target) = &opts.expected_target {
            ensure!(parts[1] == target, "HTTP target mismatch");
        }
    }
    if opts.expected_status.is_some() || opts.require_complete_response {
        let (line, headers, end) = head(t.received_unsafe(), t.received_authed())?;
        let status: u16 = line
            .split(' ')
            .nth(1)
            .ok_or_else(|| anyhow!("invalid HTTP status"))?
            .parse()?;
        if let Some(expected) = opts.expected_status {
            ensure!(status == expected, "HTTP status mismatch");
        }
        if opts.require_complete_response {
            // A strict Content-Length policy avoids accepting a transport-EOF prefix.
            // Other framing remains inspectable, but is not asserted complete here.
            ensure!(
                unique(&headers, "transfer-encoding")?.is_none(),
                "complete response policy requires Content-Length framing"
            );
            let len: usize = unique(&headers, "content-length")?
                .ok_or_else(|| anyhow!("complete response requires authenticated Content-Length"))?
                .parse()?;
            ensure!(
                t.received_unsafe().len() - end == len,
                "HTTP response is incomplete or contains trailing data"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlsn::transcript::Transcript;
    fn partial(sent: &[u8], recv: &[u8]) -> PartialTranscript {
        Transcript::new(sent, recv).to_partial((0..sent.len()).into(), (0..recv.len()).into())
    }
    #[test]
    fn authority_framing_and_freshness_fail_closed() {
        let sent = b"GET /account HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let opts = VerifyOptions {
            require_complete_response: true,
            ..Default::default()
        };
        let good = partial(sent, b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc");
        assert!(check(&good, "example.com", 0, &opts).is_ok());
        for recv in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc".as_slice(),
            b"HTTP/1.1 200 OK\r\n\r\nabc",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nabc",
        ] {
            assert!(check(&partial(sent, recv), "example.com", 0, &opts).is_err());
        }
        assert!(check(&good, "other.example", 0, &opts).is_err());
        assert!(
            check(
                &good,
                "example.com",
                0,
                &VerifyOptions {
                    max_age_secs: Some(60),
                    ..Default::default()
                }
            )
            .is_err()
        );
        assert!(
            check(
                &good,
                "example.com",
                u64::MAX,
                &VerifyOptions {
                    max_age_secs: Some(60),
                    ..Default::default()
                }
            )
            .is_err()
        );
        let hidden = Transcript::new(sent, good.received_unsafe())
            .to_partial((0..4).into(), (0..good.len_received()).into());
        assert!(check(&hidden, "example.com", 0, &opts).is_err());
    }
}
