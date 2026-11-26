use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::CoreResult;

pub fn canonical_json_string(value: &Value) -> String {
    let normalized = sort_json(value);
    serde_json::to_string(&normalized).unwrap_or_else(|_| "null".to_string())
}

fn sort_json(value: &Value) -> Value {
    match value {
        Value::Array(arr) => Value::Array(arr.iter().map(sort_json).collect()),
        Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), sort_json(v));
            }
            let mut out = serde_json::Map::with_capacity(sorted.len());
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

pub fn canonical_request_digest<T: Serialize>(payload: &T) -> String {
    let val = serde_json::to_value(payload).unwrap_or(Value::Null);
    let canonical = canonical_json_string(&val);
    sha256_bytes_prefixed(canonical.as_bytes())
}

pub fn sha256_bytes_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("sha256:{}", hex_encode(&digest))
}

pub fn sha256_file_prefixed(path: &Path) -> CoreResult<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex_encode(&hasher.finalize())))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}
