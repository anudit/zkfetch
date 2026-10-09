//! Cheap bounds checked before recursive JSON parsers run.
use anyhow::{Result, ensure};

/// Bound JSON body nesting without inspecting or disclosing scalar contents.
/// Grammar and byte authentication are checked separately by the full parser.
pub fn check_http_json_nesting(bytes: &[u8]) -> Result<()> {
    let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else { return Ok(()); };
    let head = String::from_utf8_lossy(&bytes[..end]);
    let json = head.lines().filter_map(|l| l.split_once(':')).any(|(name, value)|
        name.eq_ignore_ascii_case("content-type") && value.to_ascii_lowercase().contains("json"));
    if !json { return Ok(()); }
    check_json_nesting(&bytes[end + 4..])
}

/// Reject excessive nesting before handing bytes to recursive parsers.
pub fn check_json_nesting(bytes: &[u8]) -> Result<()> {
    let (mut depth, mut string, mut escaped) = (0usize, false, false);
    for &byte in bytes {
        if string {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { string = false; }
        } else {
            match byte {
                b'"' => string = true,
                b'{' | b'[' => { depth += 1; ensure!(depth <= 64, "JSON nesting exceeds 64 containers"); },
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nesting_limit_ignores_string_contents() {
        assert!(check_json_nesting(&vec![b'['; 65]).is_err());
        assert!(check_json_nesting(&vec![b'['; 64]).is_ok());
        let string = format!("\"{}\"", "[".repeat(1024));
        assert!(check_json_nesting(string.as_bytes()).is_ok());
    }
}
