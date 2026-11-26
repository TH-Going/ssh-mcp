use serde_json::Value;

/// Redacts all secret strings (length >= 3), both raw and JSON-escaped, replacing with `[REDACTED]`.
pub fn redact_text(input: &str, secrets: &[String]) -> String {
    if input.is_empty() || secrets.is_empty() {
        return input.to_string();
    }

    let mut candidates: Vec<String> = Vec::new();
    for secret in secrets {
        if secret.len() < 3 {
            continue;
        }
        candidates.push(secret.clone());
        if let Ok(json_str) = serde_json::to_string(secret) {
            if json_str.len() >= 2 {
                let inner = &json_str[1..json_str.len() - 1];
                if inner.len() >= 3 && inner != secret {
                    candidates.push(inner.to_string());
                    if let Ok(double_json) = serde_json::to_string(inner) {
                        if double_json.len() >= 2 {
                            let inner2 = &double_json[1..double_json.len() - 1];
                            if inner2.len() >= 3 && inner2 != inner {
                                candidates.push(inner2.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Replace longer secrets first so prefixes don't leave partial tails.
    candidates.sort_by(|a, b| b.len().cmp(&a.len()));
    candidates.dedup();

    let mut out = input.to_string();
    for needle in candidates {
        if out.contains(&needle) {
            out = out.replace(&needle, "[REDACTED]");
        }
    }
    out
}

pub fn redact_json_value(value: &Value, secrets: &[String]) -> Value {
    match value {
        Value::String(s) => Value::String(redact_text(s, secrets)),
        Value::Array(items) => Value::Array(items.iter().map(|v| redact_json_value(v, secrets)).collect()),
        Value::Object(map) => {
            let mut next = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                next.insert(k.clone(), redact_json_value(v, secrets));
            }
            Value::Object(next)
        }
        other => other.clone(),
    }
}
