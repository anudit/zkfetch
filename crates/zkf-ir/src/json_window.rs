//! Offline JSON path proofs over small windows that resume from signed
//! parser checkpoints (see `json_segment`, `checkpoint`).
//!
//! For a path `s_0 … s_{m-1}` with public anchors, each edge is proven in a
//! window that starts at the checkpoint at or before it:
//!
//! - **Member edge at level l:** at `key.start` a structural key starts at
//!   depth `l+1`, its bytes equal the encoded name, then whitespace, `:`,
//!   whitespace and a value start at `value.start`, still at depth `l+1`.
//!   For `l ≥ 1`, `stack[l]` at the key equals the parent's value position.
//!   The parent window proved a `{` push at depth `l` there, so any other
//!   container at that level would have overwritten the entry: the key is
//!   a direct member of the parent's object.
//! - **Index edge at level l:** the window starts at the array's opening
//!   bracket (or the document start), never leaves depth `> l`, and counts
//!   value starts at depth `l+1` up to the element.
//! - **Leaf:** the value extent ends exactly at `value.end` (the reference
//!   circuit's completeness check), and the caller applies the predicate.
//! - **Uniqueness (optional):** the enclosing container is parsed in full and
//!   no other direct key at depth `l+1` decodes to the same name.
//!
//! The plan depends only on public anchors, so the verifier recomputes it and
//! requires exactly the planned checkpoints to be opened.
use crate::algebra::{Algebra, Bit};
use crate::aes::ExpandedKey;
use crate::checkpoint::{self, Commitment};
use crate::json::{JsonPathSegment, PathAnchor};
use crate::json_segment::{CHECKPOINT_SPACING, LEVELS, Parser, State};
use crate::{Byte, Circuit, Wire};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    /// Inclusive body ranges, each starting at a checkpoint boundary.
    pub windows: Vec<(usize, usize)>,
    /// Checkpoint index (≥ 1) opened for each window, or 0 for the start.
    pub checkpoints: Vec<usize>,
}

fn container_open(anchors: &[PathAnchor], level: usize) -> usize {
    if level == 0 { 0 } else { anchors[level - 1].value.start }
}

/// The deterministic window plan for a path query.
pub fn plan(
    body_len: usize,
    path: &[JsonPathSegment],
    anchors: &[PathAnchor],
    unique: bool,
) -> Result<Plan, String> {
    if path.is_empty() || path.len() > LEVELS || anchors.len() != path.len() {
        return Err("invalid path".into());
    }
    let mut ranges = Vec::new();
    for (level, (step, anchor)) in path.iter().zip(anchors).enumerate() {
        let leaf = level + 1 == path.len();
        if anchor.value.start >= anchor.value.end || anchor.value.end > body_len {
            return Err("anchor outside body".into());
        }
        let end = if leaf { anchor.value.end.min(body_len - 1) } else { anchor.value.start };
        match step {
            JsonPathSegment::Member(_) => {
                if anchor.key.start >= anchor.key.end
                    || anchor.key.end > anchor.colon
                    || anchor.colon >= anchor.value.start
                {
                    return Err("invalid member anchor".into());
                }
                ranges.push((anchor.key.start, end));
                if unique {
                    let close = if level == 0 { body_len - 1 } else { anchors[level - 1].value.end - 1 };
                    ranges.push((container_open(anchors, level), close));
                }
            }
            JsonPathSegment::Index(_) => {
                if !anchor.encoded_key.is_empty() || anchor.key != (0..0) || anchor.colon != 0 {
                    return Err("invalid index anchor".into());
                }
                ranges.push((container_open(anchors, level), end));
            }
        }
        if level > 0 {
            let parent = &anchors[level - 1];
            if anchor.value.start <= parent.value.start || anchor.value.end > parent.value.end {
                return Err("anchor outside its parent".into());
            }
        }
    }
    ranges.sort();
    let mut windows: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        let start = start / CHECKPOINT_SPACING * CHECKPOINT_SPACING;
        match windows.last_mut() {
            Some(last) if start <= last.1 + 1 => last.1 = last.1.max(end),
            _ => windows.push((start, end)),
        }
    }
    let checkpoints = windows.iter().map(|(s, _)| s / CHECKPOINT_SPACING).collect();
    Ok(Plan { windows, checkpoints })
}

/// Assertions for one absolute position, collected before parsing.
#[derive(Default)]
struct At {
    /// (level) a member key starts here at depth level+1.
    key_start: Vec<usize>,
    /// (level, opened_at): stack[level] must equal opened_at before this byte.
    stack: Vec<(usize, usize)>,
    /// (level) a value starts here at depth level+1.
    value_start: Vec<usize>,
    /// Array edge at (level): the element count must equal this index here.
    index: Vec<(usize, usize)>,
    /// Never at depth <= level here (inside a container opened earlier).
    inside: Vec<usize>,
    /// Count value starts at depth level+1 strictly before the element.
    count: Vec<usize>,
    /// The container at depth level+1 closes here.
    close: Vec<usize>,
    /// Uniqueness: no other direct key at depth level+1 with this name.
    duplicate: Vec<(usize, usize)>, // (level, slot in matches)
    /// Record the leaf's depth here (value start).
    leaf_start: bool,
    /// Leaf extent: Some(true) at value.end, Some(false) inside.
    leaf_complete: Option<bool>,
    /// Document completes after this byte.
    document_end: bool,
}

/// Build the window relation. `opened[i]` is the commitment for
/// `plan.checkpoints[i]` (ignored for index 0). Returns the leaf value bytes.
#[allow(clippy::too_many_arguments)]
pub fn assert_path(
    c: &mut Circuit,
    key: &ExpandedKey,
    body: &BTreeMap<usize, Byte>,
    body_len: usize,
    plan: &Plan,
    opened: &[Commitment],
    path: &[JsonPathSegment],
    anchors: &[PathAnchor],
    unique: bool,
) -> Result<Vec<Byte>, String> {
    if opened.len() != plan.checkpoints.iter().filter(|i| **i > 0).count() {
        return Err("checkpoint openings do not match the plan".into());
    }
    let byte = |p: usize| body.get(&p).copied().ok_or_else(|| format!("byte {p} not decrypted"));
    let mut at: BTreeMap<usize, At> = BTreeMap::new();
    let leaf = path.len() - 1;
    // Uniqueness matchers per (level), over that container's window slice.
    let mut matchers: Vec<(usize, usize, Vec<Wire>)> = Vec::new(); // (level, slice start, wires)
    for (level, (step, anchor)) in path.iter().zip(anchors).enumerate() {
        let open = container_open(anchors, level);
        match step {
            JsonPathSegment::Member(name) => {
                let encoded: String = serde_json::from_slice(&anchor.encoded_key).map_err(|_| "invalid key encoding")?;
                if encoded != *name || anchor.key.len() != anchor.encoded_key.len() {
                    return Err("key encoding differs from the path".into());
                }
                for (i, expected) in anchor.encoded_key.iter().enumerate() {
                    c.assert_byte(byte(anchor.key.start + i)?, *expected);
                }
                for p in anchor.key.end..anchor.value.start {
                    if p == anchor.colon {
                        c.assert_byte(byte(p)?, b':');
                    } else {
                        let b = byte(p)?;
                        let mut a = Algebra::new(c);
                        let ws = [b' ', b'\t', b'\n', b'\r'].map(|v| a.range(b, v, v));
                        let mut any = a.public_bit(false);
                        for w in ws {
                            any = a.xor_bit(any, w);
                        }
                        a.assert_true(any);
                    }
                }
                let e = at.entry(anchor.key.start).or_default();
                e.key_start.push(level);
                if level > 0 {
                    e.stack.push((level, open));
                }
                if unique {
                    let close = if level == 0 { body_len - 1 } else { anchors[level - 1].value.end - 1 };
                    let slice: Vec<Byte> = (open..=close).map(byte).collect::<Result<_, _>>()?;
                    let mut a = Algebra::new(c);
                    a.cache_byte_classes();
                    let matches = crate::json_algebra::decoded_key_matches(&mut a, &slice, name);
                    let wires: Vec<Wire> = matches.into_iter().map(|b| a.export_bit(b)).collect();
                    drop(a);
                    let slot = matchers.len();
                    matchers.push((level, open, wires));
                    for p in open + 1..=close {
                        if p != anchor.key.start {
                            at.entry(p).or_default().duplicate.push((level, slot));
                        }
                        if level > 0 && p < close {
                            at.entry(p).or_default().inside.push(level);
                        }
                    }
                    if level > 0 {
                        at.entry(close).or_default().close.push(level);
                    } else {
                        at.entry(close).or_default().document_end = true;
                    }
                }
            }
            JsonPathSegment::Index(index) => {
                if *index >= 1 << 16 {
                    return Err("array index too large".into());
                }
                for p in open + 1..anchor.value.start {
                    let e = at.entry(p).or_default();
                    e.count.push(level);
                    if level > 0 {
                        e.inside.push(level);
                    }
                }
                at.entry(anchor.value.start).or_default().index.push((level, *index));
                if level > 0 {
                    at.entry(anchor.value.start).or_default().inside.push(level);
                }
            }
        }
        at.entry(anchor.value.start).or_default().value_start.push(level);
        if level < leaf {
            c.assert_byte(
                byte(anchor.value.start)?,
                match path[level + 1] {
                    JsonPathSegment::Member(_) => b'{',
                    JsonPathSegment::Index(_) => b'[',
                },
            );
        }
    }
    let leaf_anchor = &anchors[leaf];
    at.entry(leaf_anchor.value.start).or_default().leaf_start = true;
    for p in leaf_anchor.value.start + 1..=leaf_anchor.value.end.min(body_len - 1) {
        at.entry(p).or_default().leaf_complete = Some(p == leaf_anchor.value.end);
    }
    // Every assertion position must lie inside a window.
    for p in at.keys() {
        if !plan.windows.iter().any(|(s, e)| s <= p && p <= e) {
            return Err(format!("assertion at {p} outside the window plan"));
        }
    }

    let mut opened_iter = opened.iter();
    for (&(start, end), &index) in plan.windows.iter().zip(&plan.checkpoints) {
        let state = if index == 0 {
            State::initial(c)
        } else {
            let state = State::committed(c);
            state.assert_well_formed(c);
            checkpoint::assert_commitment(c, key, index, &state, opened_iter.next().unwrap(), false);
            state
        };
        let mut a = Algebra::new(c);
        a.cache_byte_classes();
        let mut parser = Parser::new(&mut a, &state, LEVELS);
        let mut counters: BTreeMap<usize, [Wire; 16]> = BTreeMap::new();
        let mut leaf_depth: Option<Vec<Wire>> = None;
        for p in start..=end {
            let b = byte(p)?;
            let rules = at.get(&p);
            if let Some(r) = rules {
                for (level, opened_at) in &r.stack {
                    parser.assert_stack(*level, *opened_at);
                }
            }
            let mut new_leaf_depth = None;
            let mut new_counters = Vec::new();
            parser.step(b, p, |a, ev| {
                let Some(r) = rules else { return };
                for level in &r.key_start {
                    a.assert_true(ev.key_start);
                    a.assert_true(ev.depth[level + 1]);
                }
                for level in &r.value_start {
                    a.assert_true(ev.value_start);
                    a.assert_true(ev.depth[level + 1]);
                }
                for level in &r.inside {
                    for d in &ev.depth[..=*level] {
                        a.assert_false(*d);
                    }
                }
                for (level, slot) in &r.duplicate {
                    let (_, slice_start, wires) = &matchers[*slot];
                    let direct = a.and_bit(ev.key_start, ev.depth[level + 1]);
                    let m = a.import_bit(wires[p - slice_start]);
                    let dup = a.and_bit(direct, m);
                    a.assert_false(dup);
                }
                for level in &r.close {
                    a.assert_true(ev.pop);
                    a.assert_true(ev.depth[level + 1]);
                }
                for (level, index) in &r.index {
                    a.assert_false(ev.kind[*level]);
                    let count = counters.get(level).copied();
                    for bit in 0..16 {
                        let value = match count {
                            Some(wires) => a.import_bit(wires[bit]),
                            None => a.public_bit(false),
                        };
                        if index >> bit & 1 == 1 {
                            a.assert_true(value);
                        } else {
                            a.assert_false(value);
                        }
                    }
                }
                for level in &r.count {
                    let event = a.and_bit(ev.value_start, ev.depth[level + 1]);
                    let mut carry = event;
                    let current = counters.get(level).copied();
                    let mut next = [None; 16];
                    for (bit, slot) in next.iter_mut().enumerate() {
                        let old = match current {
                            Some(wires) => a.import_bit(wires[bit]),
                            None => a.public_bit(false),
                        };
                        let next_carry = a.and_bit(old, carry);
                        let value = a.xor_bit(old, carry);
                        *slot = Some(a.export_bit(value));
                        carry = next_carry;
                    }
                    a.assert_false(carry);
                    new_counters.push((*level, next.map(|w| w.unwrap())));
                }
                if r.leaf_start {
                    new_leaf_depth = Some(ev.depth.iter().map(|d| a.export_bit(*d)).collect::<Vec<_>>());
                }
                if let (Some(expected), Some(selected)) = (r.leaf_complete, leaf_depth.as_ref()) {
                    let mut same = a.public_bit(true);
                    for (d, s) in ev.depth.iter().zip(selected) {
                        let s = a.import_bit(*s);
                        let neq = a.xor_bit(*d, s);
                        let eq = a.not_bit(neq);
                        same = a.and_bit(same, eq);
                    }
                    let complete = a.and_bit(same, ev.value_complete);
                    if expected {
                        a.assert_true(complete);
                    } else {
                        a.assert_false(complete);
                    }
                }
            });
            for (level, wires) in new_counters {
                counters.insert(level, wires);
            }
            if let Some(d) = new_leaf_depth {
                leaf_depth = Some(d);
            }
            if rules.is_some_and(|r| r.document_end) {
                parser.assert_complete();
            }
        }
    }
    (leaf_anchor.value.start..leaf_anchor.value.end).map(byte).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_inputs;
    use crate::json::values;

    /// Build the window relation directly over committed plaintext (no AES
    /// decryption) and evaluate it with the honest checkpoint states.
    fn check(body: &[u8], path: &[JsonPathSegment], anchors: &[PathAnchor], unique: bool) -> Result<Vec<u8>, String> {
        let key = [5u8; 16];
        let states = checkpoint::native_states(body)?;
        let commitments: Vec<_> = states
            .iter()
            .enumerate()
            .map(|(i, s)| checkpoint::commit_native(&key, i + 1, s))
            .collect();
        let plan = plan(body.len(), path, anchors, unique)?;
        let mut c = Circuit::default();
        let k: Vec<_> = (0..16).map(|_| c.commit_byte()).collect();
        let expanded = ExpandedKey::new(&mut c, &k).map_err(|e| e.to_string())?;
        let positions: Vec<usize> = plan.windows.iter().flat_map(|(s, e)| *s..=*e).collect();
        let bytes: BTreeMap<usize, Byte> = positions.iter().map(|p| (*p, c.commit_byte())).collect();
        let opened: Vec<_> = plan.checkpoints.iter().filter(|i| **i > 0).map(|i| commitments[i - 1]).collect();
        let value = assert_path(&mut c, &expanded, &bytes, body.len(), &plan, &opened, path, anchors, unique)?;
        let mut inputs = byte_inputs(&key);
        inputs.extend(byte_inputs(&positions.iter().map(|p| body[*p]).collect::<Vec<_>>()));
        for i in plan.checkpoints.iter().filter(|i| **i > 0) {
            inputs.extend(states[i - 1].iter().map(|b| crate::field::Fe(u128::from(*b))));
        }
        let w = c.eval(&inputs).map_err(|e| format!("{e:?}"))?;
        Ok(value.iter().map(|b| w.byte(*b)).collect())
    }

    fn member(path: &[&str]) -> Vec<JsonPathSegment> {
        path.iter().map(|s| JsonPathSegment::Member((*s).into())).collect()
    }

    fn anchors_for(body: &[u8], path: &[JsonPathSegment]) -> Vec<PathAnchor> {
        values(body).unwrap().into_iter().find(|m| m.path == path).unwrap().anchors
    }

    #[test]
    fn deep_value_proves_with_small_windows() {
        let body = format!(
            r#"{{"pad":"{}","streakData":{{"other":[1,2,3],"longestStreak":{{"length":123}}}}}}"#,
            "x".repeat(400)
        );
        let path = member(&["streakData", "longestStreak", "length"]);
        let anchors = anchors_for(body.as_bytes(), &path);
        let p = plan(body.len(), &path, &anchors, false).unwrap();
        let covered: usize = p.windows.iter().map(|(s, e)| e - s + 1).sum();
        assert!(covered < 140, "windows cover {covered} bytes: {:?}", p.windows);
        assert!(p.checkpoints.iter().all(|i| *i > 0));
        assert_eq!(check(body.as_bytes(), &path, &anchors, false).unwrap(), b"123");
    }

    #[test]
    fn sibling_and_wrong_parent_anchors_are_rejected() {
        let body = format!(
            r#"{{"a":{{"x":{{"v":1}}}},"pad":"{}","b":{{"x":{{"v":2}}}}}}"#,
            "y".repeat(100)
        );
        let path = member(&["a", "x", "v"]);
        let good = anchors_for(body.as_bytes(), &path);
        assert_eq!(check(body.as_bytes(), &path, &good, false).unwrap(), b"1");
        // Claim a.x.v but point the leaf at b.x.v (a different container).
        let other = anchors_for(body.as_bytes(), &member(&["b", "x", "v"]));
        let mut forged = good.clone();
        forged[2] = other[2].clone();
        forged[1].value = forged[1].value.start..other[2].value.end + 2;
        assert!(check(body.as_bytes(), &path, &forged, false).is_err());
        // Point the middle edge at b.x while keeping parent a.
        let mut forged = good.clone();
        forged[1] = other[1].clone();
        forged[2] = other[2].clone();
        forged[0].value = forged[0].value.start..body.len() - 1;
        assert!(check(body.as_bytes(), &path, &forged, false).is_err());
    }

    #[test]
    fn forged_parent_link_fails_in_the_circuit_not_the_plan() {
        let body = format!(
            r#"{{"a":{{"x":{{"v":1}}}},"pad":"{}","b":{{"x":{{"v":2}}}}}}"#,
            "y".repeat(100)
        );
        let path = member(&["a", "x", "v"]);
        let good = anchors_for(body.as_bytes(), &path);
        let other = anchors_for(body.as_bytes(), &member(&["b", "x", "v"]));
        // Keep a's key, but claim its object spans to the end and that b.x
        // is its direct member "x". The plan accepts the nesting; only the
        // container-stack link can reject it.
        let mut forged = vec![good[0].clone(), other[1].clone(), other[2].clone()];
        forged[0].value = good[0].value.start..body.len() - 1;
        assert!(plan(body.len(), &path, &forged, false).is_ok());
        let err = check(body.as_bytes(), &path, &forged, false).unwrap_err();
        assert!(!err.contains("plan") && !err.contains("outside"), "{err}");
        // Same for the leaf edge alone.
        let mut forged = vec![good[0].clone(), good[1].clone(), other[2].clone()];
        forged[0].value = good[0].value.start..body.len() - 1;
        forged[1].value = good[1].value.start..body.len() - 2;
        assert!(plan(body.len(), &path, &forged, false).is_ok());
        assert!(check(body.as_bytes(), &path, &forged, false).is_err());
    }

    #[test]
    fn array_index_and_uniqueness() {
        let body = format!(
            r#"{{"pad":"{}","rows":[{{"n":10}},{{"n":20}},{{"n":30}}],"dup":{{"k":1,"k":2}}}}"#,
            "z".repeat(80)
        );
        let path = vec![
            JsonPathSegment::Member("rows".into()),
            JsonPathSegment::Index(1),
            JsonPathSegment::Member("n".into()),
        ];
        let anchors = anchors_for(body.as_bytes(), &path);
        assert_eq!(check(body.as_bytes(), &path, &anchors, false).unwrap(), b"20");
        assert_eq!(check(body.as_bytes(), &path, &anchors, true).unwrap(), b"20");
        let mut wrong = path.clone();
        wrong[1] = JsonPathSegment::Index(2);
        assert!(check(body.as_bytes(), &wrong, &anchors, false).is_err());
        let dup = member(&["dup", "k"]);
        let dup_anchors = anchors_for(body.as_bytes(), &dup);
        assert!(check(body.as_bytes(), &dup, &dup_anchors, false).is_ok());
        assert!(check(body.as_bytes(), &dup, &dup_anchors, true).is_err());
    }
}
