//! Header/body block selection with authenticated TLS record boundaries.
use crate::{Byte, Circuit, aes::ExpandedKey, tls};
use zkf_attestation::{records::Direction, response::Head};

#[derive(Clone, Copy)]
pub enum Scope {
    Head,
    Body,
    Full,
}

/// Validate before allocating any circuit; all lengths come from signed
/// records. The in-session head relation proves the declared type and suffix.
pub fn body_len(direction: &Direction, head: &Head) -> Result<usize, String> {
    if head.headers.len() > 16384 || head.records.len() != direction.records.len() {
        return Err("invalid response head size or record coverage".into());
    }
    let mut total = 0usize;
    for (record, view) in direction.records.iter().zip(&head.records) {
        let inner = usize::from(record.len)
            .checked_sub(16)
            .ok_or("short record")?;
        if view.content_len >= inner || !matches!(view.inner_type, 0x15..=0x17) {
            return Err("invalid record content type or position".into());
        }
        if view.inner_type == 0x17 {
            total = total
                .checked_add(view.content_len)
                .ok_or("response overflow")?;
        }
    }
    let body = total
        .checked_sub(head.headers.len())
        .ok_or("header beyond response")?;
    if body == 0 || body > 1024 {
        return Err("JSON body outside profile cap".into());
    }
    verify_headers(&head.headers, body)?;
    Ok(body)
}

pub fn verify_headers(bytes: &[u8], body_len: usize) -> Result<(), String> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut headers);
    if response.parse(bytes).map_err(|e| e.to_string())? != httparse::Status::Complete(bytes.len())
        || response.version != Some(1)
        || response.code != Some(200)
    {
        return Err("profile requires a complete HTTP/1.1 200 head".into());
    }
    let mut length = None;
    let mut content_type = false;
    for header in response.headers {
        let value = std::str::from_utf8(header.value).map_err(|e| e.to_string())?;
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid or duplicate Content-Length".into());
            }
            length = Some(value.parse::<usize>().map_err(|e| e.to_string())?);
        } else if header.name.eq_ignore_ascii_case("content-type") {
            if content_type
                || !value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/json")
            {
                return Err("invalid or duplicate JSON Content-Type".into());
            }
            content_type = true;
        } else if header.name.eq_ignore_ascii_case("transfer-encoding")
            || header.name.eq_ignore_ascii_case("content-encoding")
        {
            return Err("chunked or compressed response unsupported".into());
        }
    }
    if !content_type || length != Some(body_len) {
        return Err("response framing mismatch".into());
    }
    Ok(())
}

/// Body scope is safe only after the verifier verifies the notary signature
/// and the exact Head digest. Full scope supports attestations without it.
pub fn decrypt(
    c: &mut Circuit,
    key: &ExpandedKey,
    direction: &Direction,
    ciphertext: &[u8],
    iv: [u8; 12],
    head: &Head,
    scope: Scope,
) -> Result<Vec<Byte>, String> {
    decrypt_with_encoding(
        c,
        key,
        direction,
        ciphertext,
        iv,
        head,
        scope,
        !matches!(scope, Scope::Head),
        None,
    )
}

/// Offline prefix proof. Authenticate all unsigned headers and every record
/// suffix, but decrypt body blocks only through the selected value delimiter.
pub fn decrypt_prefix(
    c: &mut Circuit,
    key: &ExpandedKey,
    direction: &Direction,
    ciphertext: &[u8],
    iv: [u8; 12],
    head: &Head,
    scope: Scope,
    through: usize,
) -> Result<Vec<Byte>, String> {
    if matches!(scope, Scope::Head) {
        return Err("prefix requires body scope".into());
    }
    decrypt_with_encoding(
        c,
        key,
        direction,
        ciphertext,
        iv,
        head,
        scope,
        true,
        Some(through),
    )
}

fn decrypt_with_encoding(
    c: &mut Circuit,
    key: &ExpandedKey,
    direction: &Direction,
    ciphertext: &[u8],
    iv: [u8; 12],
    head: &Head,
    scope: Scope,
    norm: bool,
    through: Option<usize>,
) -> Result<Vec<Byte>, String> {
    let size = body_len(direction, head)?;
    let limit = through.unwrap_or(size);
    if limit == 0 || limit > size {
        return Err("body prefix outside document".into());
    }
    let body_end = head.headers.len() + limit;
    let mut body = Vec::with_capacity(limit);
    let mut application_at = 0;
    for (record, view) in direction.records.iter().zip(&head.records) {
        let inner_len = usize::from(record.len) - 16;
        let start = usize::try_from(record.offset).map_err(|_| "record offset overflow")? + 5;
        let inner = ciphertext
            .get(start..start + inner_len)
            .ok_or("missing ciphertext")?;
        for (block_index, bytes) in inner.chunks(16).enumerate() {
            let first = block_index * 16;
            let last = first + bytes.len();
            let head_end = head
                .headers
                .len()
                .saturating_sub(application_at)
                .min(view.content_len);
            let is_application = view.inner_type == 0x17;
            let touches_head = is_application && first < head_end;
            let touches_body = is_application
                && last.min(view.content_len) > first.max(head_end)
                && application_at + first < body_end;
            let touches_suffix = last > view.content_len;
            let needed = match scope {
                Scope::Head => touches_head || touches_suffix,
                Scope::Body => touches_body,
                Scope::Full => !is_application || touches_head || touches_body || touches_suffix,
            };
            if !needed {
                continue;
            }
            let mut ct = [0; 16];
            ct[..bytes.len()].copy_from_slice(bytes);
            let counter = tls::counter_block(iv, record.seq, block_index as u32)
                .map_err(|e| e.to_string())?;
            let plain = if norm {
                tls::ctr_block(c, key, counter, ct, [None; 16])
            } else {
                tls::ctr_block_session(c, key, counter, ct, [None; 16])
            }
            .map_err(|e| e.to_string())?;
            for (i, byte) in plain.into_iter().enumerate().take(bytes.len()) {
                let at = first + i;
                if !matches!(scope, Scope::Body) {
                    if at == view.content_len {
                        c.assert_byte(byte, view.inner_type);
                    } else if at > view.content_len {
                        c.assert_byte(byte, 0);
                    } else if is_application && application_at + at < head.headers.len() {
                        c.assert_byte(byte, head.headers[application_at + at]);
                    }
                }
                if !matches!(scope, Scope::Head)
                    && is_application
                    && at < view.content_len
                    && application_at + at >= head.headers.len()
                    && application_at + at < body_end
                {
                    body.push(byte);
                }
            }
        }
        if view.inner_type == 0x17 {
            application_at += view.content_len;
        }
    }
    if !matches!(scope, Scope::Head) && body.len() != limit {
        return Err("body circuit coverage mismatch".into());
    }
    Ok(body)
}

/// Borrow both TLS keys, bind their OWFs, then authenticate response framing.
pub fn session(
    client: [u8; 32],
    server: [u8; 32],
    direction: &Direction,
    ciphertext: &[u8],
    iv: [u8; 12],
    head: &Head,
    claims: &[zkf_attestation::response::MemberClaim],
    checkpoints: Option<&[crate::checkpoint::Commitment]>,
) -> Result<Circuit, String> {
    let body_bytes = body_len(direction, head)?;
    if let Some(commitments) = checkpoints {
        if commitments.len() != crate::checkpoint::count(body_bytes) {
            return Err("checkpoint count does not match the response body".into());
        }
    }
    if claims.len() > 16 {
        return Err("too many session claims".into());
    }
    let mut c = Circuit::default();
    let keys: Vec<_> = (0..32).map(|_| c.commit_byte()).collect();
    for (index, (key, ck)) in keys.chunks_exact(16).zip([client, server]).enumerate() {
        let expanded = ExpandedKey::new(&mut c, key).map_err(|e| e.to_string())?;
        for (wire, expected) in tls::key_commitment_session(&mut c, &expanded)
            .into_iter()
            .zip(ck)
        {
            c.assert_byte(wire, expected);
        }
        if index == 1 {
            let body = decrypt_with_encoding(
                &mut c,
                &expanded,
                direction,
                ciphertext,
                iv,
                head,
                if claims.is_empty() && checkpoints.is_none() {
                    Scope::Head
                } else {
                    Scope::Full
                },
                false,
                if claims.is_empty() && checkpoints.is_none() {
                    None
                } else if checkpoints.is_some() {
                    Some(body_bytes)
                } else {
                    let limit = claims
                        .iter()
                        .map(|claim| {
                            if claim.unique {
                                return Ok(body_bytes);
                            }
                            claim
                                .value
                                .end
                                .checked_add(1)
                                .map(|end| end.min(body_bytes))
                                .ok_or_else(|| "claim prefix overflow".to_string())
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .max()
                        .unwrap();
                    if limit > body_bytes {
                        return Err("claim delimiter beyond response body".into());
                    }
                    Some(limit)
                },
            )?;
            if let Some(commitments) = checkpoints {
                let states = crate::json_segment::checkpoint_states(&mut c, &body);
                for (i, (state, commitment)) in states.iter().zip(commitments).enumerate() {
                    crate::checkpoint::assert_commitment(&mut c, &expanded, i + 1, state, commitment, true);
                }
            }
            for claim in claims {
                if claim.member.len() > 1024
                    || serde_json::from_slice::<String>(&claim.encoded_key)
                        .map_err(|e| e.to_string())?
                        != claim.member
                {
                    return Err("invalid session member encoding".into());
                }
                let comparison = match claim.op.as_str() {
                    "eq" => crate::predicates::Comparison::Eq,
                    "ne" => crate::predicates::Comparison::Ne,
                    "lt" => crate::predicates::Comparison::Lt,
                    "le" => crate::predicates::Comparison::Le,
                    "gt" => crate::predicates::Comparison::Gt,
                    "ge" => crate::predicates::Comparison::Ge,
                    _ => return Err("invalid session comparison".into()),
                };
                let selected = if claim.is_path() {
                    let leaf = claim.anchors.last().ok_or("path claim without anchors")?;
                    if claim.path.is_empty()
                        || claim.anchors.len() != claim.path.len()
                        || leaf.encoded_key != claim.encoded_key
                        || leaf.key != claim.key
                        || leaf.colon != claim.colon
                        || leaf.value != claim.value
                        || !(1..=8).contains(&claim.max_depth)
                    {
                        return Err("inconsistent path claim".into());
                    }
                    if let Some(crate::json::JsonPathSegment::Member(name)) = claim.path.last() {
                        if *name != claim.member {
                            return Err("path leaf differs from claim member".into());
                        }
                    }
                    let document = if claim.unique {
                        &body[..]
                    } else {
                        &body[..(claim.value.end + 1).min(body.len())]
                    };
                    crate::json_algebra::path_member_bounded(
                        &mut c,
                        document,
                        &claim.path,
                        &claim.anchors,
                        claim.unique,
                        usize::from(claim.max_depth),
                    )
                } else {
                    if !claim.anchors.is_empty() || claim.max_depth != 4 {
                        return Err("root member claim with path metadata".into());
                    }
                    crate::json_algebra::top_level_member(
                        &mut c,
                        &body,
                        &crate::json_circuit::Selection {
                            encoded_key: &claim.encoded_key,
                            key: claim.key.clone(),
                            colon: claim.colon,
                            value: claim.value.clone(),
                        },
                        4,
                        true,
                    )
                }
                .map_err(|e| e.to_string())?;
                let value =
                    crate::predicates::ascii_u64(&mut c, &selected).map_err(|e| e.to_string())?;
                let constant = crate::predicates::U64::public(&mut c, claim.constant);
                value.assert_compare(&mut c, constant, comparison);
            }
        }
    }
    c.register_profile(if checkpoints.is_some() {
        SESSION_CHECKPOINT_PROFILE
    } else {
        SESSION_PROFILE
    });
    Ok(c)
}

/// Fixed offline relation; all builder inputs must be bound by the integration.
pub fn offline_relation(
    commitment: [u8; 32],
    direction: &Direction,
    ciphertext: &[u8],
    iv: [u8; 12],
    head: &Head,
    signed_head: bool,
    selection: &crate::json_circuit::Selection<'_>,
    comparison: crate::predicates::Comparison,
    constant: u64,
) -> Result<Circuit, String> {
    offline_relation_path(
        commitment,
        direction,
        ciphertext,
        iv,
        head,
        signed_head,
        selection,
        comparison,
        constant,
        None,
    )
}

pub fn offline_relation_path(
    commitment: [u8; 32],
    direction: &Direction,
    ciphertext: &[u8],
    iv: [u8; 12],
    head: &Head,
    signed_head: bool,
    selection: &crate::json_circuit::Selection<'_>,
    comparison: crate::predicates::Comparison,
    constant: u64,
    path: Option<(
        &[crate::json::JsonPathSegment],
        &[crate::json::PathAnchor],
        bool,
        usize,
    )>,
) -> Result<Circuit, String> {
    let size = body_len(direction, head)?;
    let mut c = Circuit::default();
    let refs: Vec<_> = (0..16).map(|_| c.commit_byte()).collect();
    let expanded = ExpandedKey::new(&mut c, &refs).map_err(|e| e.to_string())?;
    for (wire, expected) in tls::key_commitment(&mut c, &expanded)
        .into_iter()
        .zip(commitment)
    {
        c.assert_byte(wire, expected);
    }
    let body = decrypt_prefix(
        &mut c,
        &expanded,
        direction,
        ciphertext,
        iv,
        head,
        if signed_head {
            Scope::Body
        } else {
            Scope::Full
        },
        if path.is_some_and(|(_, _, unique, _)| unique) {
            size
        } else {
            selection.value.end.saturating_add(1).min(size)
        },
    )?;
    let selected = if let Some((steps, anchors, unique, depth)) = path {
        crate::json_algebra::path_member_bounded(&mut c, &body, steps, anchors, unique, depth)
    } else {
        crate::json_algebra::top_level_member(&mut c, &body, selection, 4, true)
    }
    .map_err(|e| e.to_string())?;
    let value = crate::predicates::ascii_u64(&mut c, &selected).map_err(|e| e.to_string())?;
    let constant = crate::predicates::U64::public(&mut c, constant);
    value.assert_compare(&mut c, constant, comparison);
    c.register_profile(if path.is_some() {
        if signed_head {
            OFFLINE_PATH_BODY_PROFILE
        } else {
            OFFLINE_PATH_FULL_PROFILE
        }
    } else if signed_head {
        OFFLINE_BODY_PROFILE
    } else {
        OFFLINE_FULL_PROFILE
    });
    Ok(c)
}
pub const OFFLINE_FULL_PROFILE: &str =
    "zkf/2/http-json/compact-aes/prefix/top-level/depth-4/full/v4";
pub const OFFLINE_BODY_PROFILE: &str =
    "zkf/2/http-json/compact-aes/prefix/top-level/depth-4/signed-head/v4";
pub const SESSION_PROFILE: &str = "zkf/2/session/standard-aes/prefix/member-or-path/v6";
pub const SESSION_CHECKPOINT_PROFILE: &str =
    "zkf/2/session/standard-aes/full-body/json-checkpoints-32/member-or-path/v1";
pub const OFFLINE_PATH_FULL_PROFILE: &str = "zkf/2/http-json/compact-aes/path/bounded-depth-8/full/v7";
pub const OFFLINE_PATH_BODY_PROFILE: &str =
    "zkf/2/http-json/compact-aes/path/bounded-depth-8/signed-head/v7";
