//! Reference semantics for structural JSON member anchors.
//! A future circuit must authenticate the parser state used here; this plain
//! parser is not a ZK gadget and must not be substituted for one by a verifier.
use core::ops::Range;
pub use zkf_attestation::response::{JsonPathSegment, PathAnchor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub key: String,
    /// Object depth: zero identifies members of the root object.
    pub object_depth: usize,
    /// Includes both quotes around the key, retaining the actual escape form.
    pub key_range: Range<usize>,
    pub value_range: Range<usize>,
    pub path: Vec<JsonPathSegment>,
    pub anchors: Vec<PathAnchor>,
}

#[derive(Debug, thiserror::Error)]
pub enum JsonError {
    #[error("JSON exceeds the reference parser's byte limit")]
    Size,
    #[error("JSON nesting exceeds the reference parser's depth limit")]
    Depth,
    #[error("invalid JSON")]
    Syntax,
}

/// Collect members across all objects, preserving duplicate member names.
/// T2 selects one authenticated member span; it does not assert a JSON path,
/// uniqueness, root-object membership, or the absence of duplicate names.
pub fn members(document: &[u8]) -> Result<Vec<Member>, JsonError> {
    Ok(values(document)?
        .into_iter()
        .filter(|v| !v.key_range.is_empty())
        .collect())
}

/// Object members and array elements, retaining exact typed paths and spans.
pub fn values(document: &[u8]) -> Result<Vec<Member>, JsonError> {
    if document.len() > 8 << 20 {
        return Err(JsonError::Size);
    }
    // Validate strings, UTF-8, numbers, escapes, and the entire grammar first.
    // Do not use the resulting Value for member selection: it drops duplicates.
    serde_json::from_slice::<serde_json::Value>(document).map_err(|_| JsonError::Syntax)?;
    let mut p = Parser {
        data: document,
        at: 0,
        members: Vec::new(),
        path: Vec::new(),
        anchors: Vec::new(),
    };
    p.value(0)?;
    p.whitespace();
    if p.at != document.len() {
        return Err(JsonError::Syntax);
    }
    Ok(p.members)
}

struct Parser<'a> {
    data: &'a [u8],
    at: usize,
    members: Vec<Member>,
    path: Vec<JsonPathSegment>,
    anchors: Vec<PathAnchor>,
}
impl Parser<'_> {
    fn whitespace(&mut self) {
        while self
            .data
            .get(self.at)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.at += 1;
        }
    }
    fn eat(&mut self, expected: u8) -> Result<(), JsonError> {
        self.whitespace();
        if self.data.get(self.at) != Some(&expected) {
            return Err(JsonError::Syntax);
        }
        self.at += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<Range<usize>, JsonError> {
        self.whitespace();
        let start = self.at;
        self.eat(b'"')?;
        loop {
            match self.data.get(self.at) {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(start..self.at);
                }
                Some(b'\\') => self.at += 2,
                Some(_) => self.at += 1,
                None => return Err(JsonError::Syntax),
            }
        }
    }
    fn value(&mut self, depth: usize) -> Result<Range<usize>, JsonError> {
        if depth > 64 {
            return Err(JsonError::Depth);
        }
        self.whitespace();
        let start = self.at;
        match self.data.get(self.at) {
            Some(b'"') => {
                self.string()?;
            }
            Some(b'{') => {
                self.at += 1;
                self.whitespace();
                if self.data.get(self.at) != Some(&b'}') {
                    loop {
                        let key_range = self.string()?;
                        let key: String = serde_json::from_slice(&self.data[key_range.clone()])
                            .map_err(|_| JsonError::Syntax)?;
                        self.whitespace();
                        let colon = self.at;
                        self.eat(b':')?;
                        self.whitespace();
                        let value_start = self.at;
                        self.path.push(JsonPathSegment::Member(key.clone()));
                        self.anchors.push(PathAnchor {
                            encoded_key: self.data[key_range.clone()].to_vec(),
                            key: key_range.clone(),
                            colon,
                            value: value_start..value_start,
                        });
                        let first_descendant = self.members.len();
                        let value_range = self.value(depth + 1)?;
                        for member in &mut self.members[first_descendant..] {
                            member.anchors[depth].value = value_range.clone();
                        }
                        self.anchors.last_mut().unwrap().value = value_range.clone();
                        self.members.push(Member {
                            key,
                            object_depth: depth,
                            key_range,
                            value_range,
                            path: self.path.clone(),
                            anchors: self.anchors.clone(),
                        });
                        self.path.pop();
                        self.anchors.pop();
                        self.whitespace();
                        if self.data.get(self.at) == Some(&b'}') {
                            break;
                        }
                        self.eat(b',')?;
                    }
                }
                self.eat(b'}')?;
            }
            Some(b'[') => {
                self.at += 1;
                self.whitespace();
                if self.data.get(self.at) != Some(&b']') {
                    let mut index = 0;
                    loop {
                        self.whitespace();
                        let start = self.at;
                        self.path.push(JsonPathSegment::Index(index));
                        self.anchors.push(PathAnchor {
                            encoded_key: Vec::new(),
                            key: 0..0,
                            colon: 0,
                            value: start..start,
                        });
                        let first_descendant = self.members.len();
                        let value_range = self.value(depth + 1)?;
                        for member in &mut self.members[first_descendant..] {
                            member.anchors[depth].value = value_range.clone();
                        }
                        self.anchors.last_mut().unwrap().value = value_range.clone();
                        self.members.push(Member {
                            key: String::new(),
                            object_depth: depth,
                            key_range: 0..0,
                            value_range,
                            path: self.path.clone(),
                            anchors: self.anchors.clone(),
                        });
                        self.path.pop();
                        self.anchors.pop();
                        index += 1;
                        self.whitespace();
                        if self.data.get(self.at) == Some(&b']') {
                            break;
                        }
                        self.eat(b',')?;
                    }
                }
                self.eat(b']')?;
            }
            Some(_) => {
                while self.data.get(self.at).is_some_and(|b| {
                    !matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b',' | b']' | b'}')
                }) {
                    self.at += 1;
                }
                if self.at == start {
                    return Err(JsonError::Syntax);
                }
            }
            None => return Err(JsonError::Syntax),
        }
        Ok(start..self.at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    #[test]
    fn local_quote_parity_is_not_structural_membership() {
        // Both quotes in the substring `", "` are unescaped. The first closes
        // the value "x"; the second opens the next member name. A local lexer
        // would see a fake member named comma-space, followed by : 7,.
        let body = br#"{"a":"x", ": 7, hidden":0}"#;
        assert!(body.windows(8).any(|w| w == b"\", \": 7,"));
        let found = members(body).unwrap();
        assert!(found.iter().all(|m| m.key != ", "));
        assert!(found.iter().any(|m| m.key == ": 7, hidden"));
    }
    #[test]
    fn escaped_keys_and_duplicate_members_preserve_spans() {
        let body = br#"{"\u0069d":1,"id":2,"nested":[{"id":"a\\\"b"}]}"#;
        let found = members(body).unwrap();
        let ids: Vec<_> = found.iter().filter(|m| m.key == "id").collect();
        assert_eq!(ids.len(), 3);
        assert_eq!(&body[ids[0].value_range.clone()], b"1");
        assert_eq!(&body[ids[1].value_range.clone()], b"2");
        assert!(serde_json::from_slice::<String>(&body[ids[2].value_range.clone()]).is_ok());
    }
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]
        #[test]
        fn escaping_whitespace_and_nested_values(key in ".{0,32}", value in ".{0,64}", ws in "[ \t\n\r]{0,12}") {
            let encoded_key = serde_json::to_string(&key).unwrap();
            let encoded_value = serde_json::to_string(&value).unwrap();
            let body = format!("{{{ws}{encoded_key}{ws}:{ws}[{{\"inner\":{encoded_value}}}]{ws}}}");
            let found = members(body.as_bytes()).unwrap();
            prop_assert!(found.iter().any(|m| m.key == key));
            for member in &found {
                let selected: serde_json::Value = serde_json::from_slice(&body.as_bytes()[member.value_range.clone()]).unwrap();
                if member.key == "inner" && selected.is_string() { prop_assert_eq!(selected, serde_json::json!(value)); }
            }
        }
    }
}

/// Public allocation hint only. The circuit independently authenticates stack
/// transitions and rejects overflow; this scanner is never a verifier oracle.
/// Accepts a prefix ending at the selected value delimiter.
pub fn required_depth(prefix: &[u8]) -> usize {
    let (mut quoted, mut escaped, mut depth, mut peak) = (false, false, 0usize, 0usize);
    for &byte in prefix {
        if quoted {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { quoted = false; }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => { depth += 1; peak = peak.max(depth); }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {},
            }
        }
    }
    peak.max(1)
}
