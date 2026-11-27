#[path = "../../ssh-mcp-core/src/skills_bundle.rs"]
mod skills_bundle;

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--install-skills") {
        let explicit_dir = parse_flag_value(&args, "--skills-dir").map(PathBuf::from);
        match skills_bundle::auto_install_skills(None, explicit_dir.as_deref()) {
            Ok(report) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
                );
                return;
            }
            Err(err) => {
                eprintln!("安装 ssh-mcp Skills 失败: {err}");
                std::process::exit(1);
            }
        }
    }

    let endpoint = parse_endpoint_arg(&args);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(320))
        .no_proxy()
        .build()
        .expect("Failed to initialize HTTP client");

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut lines = BufReader::new(stdin).lines();
    let mut session_id: Option<String> = None;

    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parsed: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("Invalid JSON: {e}") }
                });
                let _ = write_json_line(&mut stdout, &err_resp).await;
                continue;
            }
        };

        let is_init = parsed.get("method").and_then(|m| m.as_str()) == Some("initialize");
        let init_client_name = if is_init {
            parsed
                .get("params")
                .and_then(|p| p.get("clientInfo"))
                .and_then(|c| c.get("name"))
                .and_then(|n| n.as_str())
                .map(ToString::to_string)
        } else {
            None
        };

        let req_id = parsed.get("id").cloned();

        let mut req_builder = client
            .post(&endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json");

        if let Some(sid) = &session_id {
            req_builder = req_builder.header("mcp-session-id", sid);
        }

        match req_builder.body(trimmed.to_string()).send().await {
            Ok(resp) => {
                if let Some(sid) = resp
                    .headers()
                    .get("mcp-session-id")
                    .and_then(|v| v.to_str().ok())
                {
                    session_id = Some(sid.to_string());
                }

                let status = resp.status();
                if status == reqwest::StatusCode::ACCEPTED
                    || status == reqwest::StatusCode::NO_CONTENT
                {
                    continue;
                }

                match resp.text().await {
                    Ok(body) if !body.trim().is_empty() => {
                        if let Ok(json_val) = serde_json::from_str::<Value>(&body) {
                            let _ = write_json_line(&mut stdout, &json_val).await;
                        } else if let Some(id) = req_id {
                            let err_resp = json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": {
                                    "code": -32603,
                                    "message": format!("MCP HTTP {status}: {body}")
                                }
                            });
                            let _ = write_json_line(&mut stdout, &err_resp).await;
                        }
                    }
                    _ => {}
                }
            }
            Err(err) => {
                // Fallback: if the desktop HTTP server is offline during initialize, still ensure local skills exist
                // (protected against downgrading newer app skills by semver check in `install_skills_to_dir`).
                if is_init {
                    let cname = init_client_name.clone();
                    tokio::task::spawn_blocking(move || {
                        let _ = skills_bundle::auto_install_skills(cname.as_deref(), None);
                    });
                }
                if let Some(id) = req_id {
                    let err_resp = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32000,
                            "message": format!(
                                "无法连接本地服务器控制台 MCP 服务 ({endpoint})，请确认桌面端已启动且已开启「MCP 服务」开关。底层原因: {err}"
                            )
                        }
                    });
                    let _ = write_json_line(&mut stdout, &err_resp).await;
                }
            }
        }
    }
}

async fn write_json_line(stdout: &mut tokio::io::Stdout, val: &Value) -> std::io::Result<()> {
    let serialized = serde_json::to_string(val).unwrap_or_else(|_| "{}".to_string());
    stdout.write_all(serialized.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await
}

fn parse_flag_value(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            return iter.next().cloned().filter(|s| !s.trim().is_empty());
        }
        if let Some(rest) = arg.strip_prefix(&format!("{flag}=")) {
            if !rest.trim().is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    None
}

fn parse_endpoint_arg(args: &[String]) -> String {
    if let Some(val) = parse_flag_value(args, "--endpoint") {
        return normalize_endpoint(&val);
    }
    if let Ok(env_url) = std::env::var("SSH_MCP_ENDPOINT") {
        if !env_url.trim().is_empty() {
            return normalize_endpoint(&env_url);
        }
    }
    "http://127.0.0.1:8787/mcp".to_string()
}

fn normalize_endpoint(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.ends_with("/mcp") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/mcp")
    }
}
