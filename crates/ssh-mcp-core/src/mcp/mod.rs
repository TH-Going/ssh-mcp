use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::db::AppDatabase;
use crate::error::{CoreError, CoreResult};
use crate::jobs::JobService;
use crate::models::{
    DockerCleanupPolicy, DockerContainerStateFilter, JobCreateRequest, JobWaitRequest,
    ServiceControlAction, ServiceStateFilter, ToolOperation, WaitUntilMode,
};

const MCP_PROTOCOL_VERSION: &str = "2025-03-26";
const SERVER_INSTRUCTIONS: &str = "通过本机服务器控制台 (sshMcp) 安全管理已配置的 Linux 服务器。服务器配置、加密凭据和主机密钥指纹仅可在桌面控制台中修改。远程操作会创建持久任务；处于「需审批」模式的服务器或包含卷删除的操作会进入待审批队列，请使用 job_wait 等待既有任务完成或审批变化，切勿通过重复创建任务进行轮询；Docker 场景优先使用结构化专用工具。";

#[derive(Debug, Clone)]
struct McpSessionMeta {
    client_name: String,
}

#[derive(Clone)]
pub struct McpRouterState {
    db: Arc<AppDatabase>,
    jobs: Arc<JobService>,
    sessions: Arc<Mutex<HashMap<String, McpSessionMeta>>>,
}

impl McpRouterState {
    pub fn new(db: Arc<AppDatabase>, jobs: Arc<JobService>) -> Self {
        Self {
            db,
            jobs,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

pub struct McpServerController {
    state: McpRouterState,
    active_token: Mutex<Option<CancellationToken>>,
    running: Arc<AtomicBool>,
}

impl McpServerController {
    pub fn new(db: Arc<AppDatabase>, jobs: Arc<JobService>) -> Arc<Self> {
        Arc::new(Self {
            state: McpRouterState::new(db, jobs),
            active_token: Mutex::new(None),
            running: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub async fn start(&self, port: u16) -> CoreResult<SocketAddr> {
        self.stop();

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(addr).await.map_err(|e| {
            CoreError::Io(std::io::Error::new(
                e.kind(),
                format!("无法绑定本地 MCP 端口 127.0.0.1:{port}: {e}"),
            ))
        })?;
        let local_addr = listener.local_addr()?;

        let cancel = CancellationToken::new();
        *self.active_token.lock() = Some(cancel.clone());
        self.running.store(true, Ordering::SeqCst);

        let router = build_mcp_router(self.state.clone());
        let running_flag = Arc::clone(&self.running);

        tokio::spawn(async move {
            let server = axum::serve(listener, router).with_graceful_shutdown(async move {
                cancel.cancelled().await;
            });
            let _ = server.await;
            running_flag.store(false, Ordering::SeqCst);
        });

        Ok(local_addr)
    }

    pub fn stop(&self) {
        if let Some(tok) = self.active_token.lock().take() {
            tok.cancel();
        }
        self.running.store(false, Ordering::SeqCst);
    }
}

pub fn build_mcp_router(state: McpRouterState) -> Router {
    Router::new()
        .route("/health", get(handle_health))
        .route(
            "/mcp",
            post(handle_mcp_post)
                .get(handle_mcp_get)
                .delete(handle_mcp_delete),
        )
        .with_state(state)
}

async fn handle_health(headers: HeaderMap) -> Response {
    if let Err(resp) = verify_loopback_headers(&headers) {
        return resp;
    }
    Json(json!({ "ok": true, "service": "ssh-mcp" })).into_response()
}

async fn handle_mcp_get(headers: HeaderMap) -> Response {
    if let Err(resp) = verify_loopback_headers(&headers) {
        return resp;
    }
    (StatusCode::METHOD_NOT_ALLOWED, "SSE stream not required; use POST /mcp").into_response()
}

async fn handle_mcp_delete(
    State(state): State<McpRouterState>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = verify_loopback_headers(&headers) {
        return resp;
    }
    if let Some(sid) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        state.sessions.lock().remove(sid);
    }
    StatusCode::NO_CONTENT.into_response()
}

fn verify_loopback_headers(headers: &HeaderMap) -> Result<(), Response> {
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        let lower = origin.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") || lower == "null" {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "拒绝来自浏览器跨站 Origin 的本地 MCP 访问" })),
            )
                .into_response());
        }
    }

    if let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) {
        let host_only = host
            .strip_prefix('[')
            .and_then(|s| s.split(']').next())
            .unwrap_or_else(|| host.split(':').next().unwrap_or(host));
        if !matches!(host_only, "127.0.0.1" | "localhost" | "::1") {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "非法 Host 请求头" })),
            )
                .into_response());
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcErrorObj>,
}

#[derive(Debug, Serialize)]
struct JsonRpcErrorObj {
    code: i32,
    message: String,
}

async fn handle_mcp_post(
    State(state): State<McpRouterState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Err(resp) = verify_loopback_headers(&headers) {
        return resp;
    }

    let parsed: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            let err = JsonRpcResponse {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(JsonRpcErrorObj {
                    code: -32700,
                    message: format!("JSON 解析错误: {e}"),
                }),
            };
            return Json(err).into_response();
        }
    };

    let mut session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);

    let header_client_name = headers
        .get("x-ssh-mcp-client")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);

    if let Some(arr) = parsed.as_array() {
        let mut responses = Vec::new();
        for item in arr {
            if let Ok(req) = serde_json::from_value::<JsonRpcRequest>(item.clone()) {
                if let Some(resp) =
                    dispatch_rpc(&state, req, &mut session_id, header_client_name.as_deref()).await
                {
                    responses.push(resp);
                }
            }
        }
        if responses.is_empty() {
            return StatusCode::ACCEPTED.into_response();
        }
        return with_session_header(Json(responses).into_response(), session_id.as_deref());
    }

    let req: JsonRpcRequest = match serde_json::from_value(parsed) {
        Ok(r) => r,
        Err(e) => {
            let err = JsonRpcResponse {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(JsonRpcErrorObj {
                    code: -32600,
                    message: format!("无效的 JSON-RPC 请求: {e}"),
                }),
            };
            return Json(err).into_response();
        }
    };

    match dispatch_rpc(&state, req, &mut session_id, header_client_name.as_deref()).await {
        Some(resp) => with_session_header(Json(resp).into_response(), session_id.as_deref()),
        None => with_session_header(StatusCode::ACCEPTED.into_response(), session_id.as_deref()),
    }
}

fn with_session_header(mut resp: Response, session_id: Option<&str>) -> Response {
    if let Some(sid) = session_id {
        if let Ok(val) = HeaderValue::from_str(sid) {
            resp.headers_mut().insert("mcp-session-id", val);
        }
    }
    resp
}

async fn dispatch_rpc(
    state: &McpRouterState,
    req: JsonRpcRequest,
    session_id: &mut Option<String>,
    header_client_name: Option<&str>,
) -> Option<JsonRpcResponse> {
    let id = req.id.clone()?;

    let requester = session_id
        .as_deref()
        .and_then(|sid| state.sessions.lock().get(sid).map(|m| m.client_name.clone()))
        .or_else(|| header_client_name.map(ToString::to_string))
        .unwrap_or_else(|| "MCP 客户端".to_string());

    let res = match req.method.as_str() {
        "initialize" => {
            let client_name = req
                .params
                .get("clientInfo")
                .and_then(|c| c.get("name"))
                .and_then(|n| n.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("MCP 客户端")
                .to_string();
            let requested_proto = req
                .params
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .unwrap_or(MCP_PROTOCOL_VERSION);

            let sid = Uuid::new_v4().to_string();
            state.sessions.lock().insert(
                sid.clone(),
                McpSessionMeta {
                    client_name: client_name.clone(),
                },
            );
            *session_id = Some(sid);

            // Automatically sync embedded ssh-mcp skills into the local AI client's skills directory!
            let cn = client_name.clone();
            tokio::task::spawn_blocking(move || {
                let _ = crate::skills_bundle::auto_install_skills(Some(&cn), None);
            });

            Ok(json!({
                "protocolVersion": requested_proto,
                "capabilities": {
                    "tools": { "listChanged": false }
                },
                "serverInfo": {
                    "name": "ssh-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "instructions": SERVER_INSTRUCTIONS
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": mcp_tools_catalog() })),
        "tools/call" => {
            let tool_name = req
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args = req
                .params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));

            match invoke_mcp_tool(state, tool_name, args, &requester).await {
                Ok(val) => Ok(mcp_tool_ok(val)),
                Err(err) => Ok(mcp_tool_err(&err.to_string())),
            }
        }
        other => Err(JsonRpcErrorObj {
            code: -32601,
            message: format!("未知的 MCP 方法: {other}"),
        }),
    };

    match res {
        Ok(result) => Some(JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }),
        Err(error) => Some(JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(error),
        }),
    }
}

fn mcp_tool_ok(value: Value) -> Value {
    let pretty = serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string());
    json!({
        "content": [{ "type": "text", "text": pretty }],
        "structuredContent": value
    })
}

fn mcp_tool_err(message: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true
    })
}

async fn invoke_mcp_tool(
    state: &McpRouterState,
    name: &str,
    args: Value,
    requester: &str,
) -> CoreResult<Value> {
    match name {
        "servers_list" => {
            let servers = state.db.list_servers()?;
            Ok(serde_json::to_value(json!({ "items": servers }))?)
        }
        "server_check" => {
            let server_ids = parse_server_ids(&args)?;
            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids,
                    operation: ToolOperation::ServerCheck,
                    requester: Some(requester.to_string()),
                    reason: None,
                })
                .await?;
            Ok(serde_json::to_value(job)?)
        }
        "system_summary" => {
            let server_ids = parse_server_ids(&args)?;
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids,
                    operation: ToolOperation::SystemSummary { timeout_seconds },
                    requester: Some(requester.to_string()),
                    reason: None,
                })
                .await?;
            Ok(serde_json::to_value(job)?)
        }
        "processes_list" => {
            let server_ids = parse_server_ids(&args)?;
            let limit = opt_u32(&args, "limit").unwrap_or(50).clamp(1, 500);
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids,
                    operation: ToolOperation::ProcessesList {
                        limit,
                        timeout_seconds,
                    },
                    requester: Some(requester.to_string()),
                    reason: None,
                })
                .await?;
            Ok(serde_json::to_value(job)?)
        }
        "services_list" => {
            let server_ids = parse_server_ids(&args)?;
            let state_filter = match args.get("state").and_then(|v| v.as_str()).unwrap_or("running") {
                "failed" => ServiceStateFilter::Failed,
                "active" => ServiceStateFilter::Active,
                "inactive" => ServiceStateFilter::Inactive,
                _ => ServiceStateFilter::Running,
            };
            let limit = opt_u32(&args, "limit").unwrap_or(100).clamp(1, 500);
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids,
                    operation: ToolOperation::ServicesList {
                        state: state_filter,
                        limit,
                        timeout_seconds,
                    },
                    requester: Some(requester.to_string()),
                    reason: None,
                })
                .await?;
            Ok(serde_json::to_value(job)?)
        }
        "service_status" => {
            let server_ids = parse_server_ids(&args)?;
            let service = req_str(&args, "service")?;
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids,
                    operation: ToolOperation::ServiceStatus {
                        service,
                        timeout_seconds,
                    },
                    requester: Some(requester.to_string()),
                    reason: None,
                })
                .await?;
            Ok(serde_json::to_value(job)?)
        }
        "service_control" => {
            let server_ids = parse_server_ids(&args)?;
            let service = req_str(&args, "service")?;
            let action = match req_str(&args, "action")?.as_str() {
                "start" => ServiceControlAction::Start,
                "stop" => ServiceControlAction::Stop,
                "restart" => ServiceControlAction::Restart,
                "reload" => ServiceControlAction::Reload,
                other => {
                    return Err(CoreError::InvalidInput(format!(
                        "无效的服务操作动作: {other}"
                    )))
                }
            };
            let sudo = opt_bool(&args, "sudo", false);
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let reason = opt_str(&args, "reason");
            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids,
                    operation: ToolOperation::ServiceControl {
                        service,
                        action,
                        sudo,
                        timeout_seconds,
                        reason: reason.clone(),
                    },
                    requester: Some(requester.to_string()),
                    reason,
                })
                .await?;
            Ok(serde_json::to_value(job)?)
        }
        "logs_query" => {
            let server_ids = parse_server_ids(&args)?;
            let unit = opt_str(&args, "unit");
            let lines = opt_u32(&args, "lines").unwrap_or(200).clamp(1, 5000);
            let since = opt_str(&args, "since");
            let query = opt_str(&args, "query");
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids,
                    operation: ToolOperation::LogsQuery {
                        unit,
                        lines,
                        since,
                        query,
                        timeout_seconds,
                    },
                    requester: Some(requester.to_string()),
                    reason: None,
                })
                .await?;
            Ok(serde_json::to_value(job)?)
        }
        "shell_execute" => {
            let server_ids = parse_server_ids(&args)?;
            let command = req_str(&args, "command")?;
            let sudo = opt_bool(&args, "sudo", false);
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let reason = opt_str(&args, "reason");
            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids,
                    operation: ToolOperation::ShellExecute {
                        command,
                        sudo,
                        timeout_seconds,
                        reason: reason.clone(),
                    },
                    requester: Some(requester.to_string()),
                    reason,
                })
                .await?;
            Ok(serde_json::to_value(job)?)
        }
        "file_upload" => {
            let server_ids = parse_server_ids(&args)?;
            let local_path = req_str(&args, "localPath")?;
            let remote_path = req_str(&args, "remotePath")?;
            let overwrite = opt_bool(&args, "overwrite", false);
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let reason = opt_str(&args, "reason");
            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids,
                    operation: ToolOperation::FileUpload {
                        local_path,
                        remote_path,
                        overwrite,
                        timeout_seconds,
                        reason: reason.clone(),
                    },
                    requester: Some(requester.to_string()),
                    reason,
                })
                .await?;
            Ok(serde_json::to_value(job)?)
        }
        "file_download" => {
            let server_ids = parse_server_ids(&args)?;
            let remote_path = req_str(&args, "remotePath")?;
            let local_path = req_str(&args, "localPath")?;
            let overwrite = opt_bool(&args, "overwrite", false);
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let reason = opt_str(&args, "reason");
            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids,
                    operation: ToolOperation::FileDownload {
                        remote_path,
                        local_path,
                        overwrite,
                        timeout_seconds,
                        reason: reason.clone(),
                    },
                    requester: Some(requester.to_string()),
                    reason,
                })
                .await?;
            Ok(serde_json::to_value(job)?)
        }
        "jobs_list" => {
            let limit = opt_u32(&args, "limit").unwrap_or(30).clamp(1, 100) as usize;
            let jobs = state.db.list_jobs(limit)?;
            Ok(serde_json::to_value(json!({ "items": jobs }))?)
        }
        "job_get" => {
            let job_id = req_str(&args, "jobId")?;
            let job = state
                .db
                .get_job(&job_id)?
                .ok_or_else(|| CoreError::NotFound("任务不存在".to_string()))?;
            Ok(serde_json::to_value(job)?)
        }
        "job_wait" => {
            let job_id = req_str(&args, "jobId")?;
            let after_revision = args.get("afterRevision").and_then(|v| v.as_i64());
            let wait_ms = args
                .get("waitMs")
                .and_then(|v| v.as_u64())
                .unwrap_or(120_000)
                .min(300_000);
            let until = match args.get("until").and_then(|v| v.as_str()) {
                Some("change") => WaitUntilMode::Change,
                _ => WaitUntilMode::TerminalOrAttention,
            };
            let res = state
                .jobs
                .wait(JobWaitRequest {
                    job_id,
                    after_revision,
                    wait_ms,
                    until,
                })
                .await?;
            Ok(serde_json::to_value(res)?)
        }
        "job_output_read" => {
            let job_id = req_str(&args, "jobId")?;
            let target_id = req_str(&args, "targetId")?;
            let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
            let limit_bytes = opt_u32(&args, "limitBytes").unwrap_or(65536) as usize;
            let cursor = opt_str(&args, "cursor");
            let out = state
                .jobs
                .read_output(&job_id, &target_id, offset, limit_bytes, cursor.as_deref())?;
            Ok(serde_json::to_value(out)?)
        }
        "job_cancel" => {
            let job_id = req_str(&args, "jobId")?;
            let job = state.jobs.cancel(&job_id)?;
            Ok(serde_json::to_value(job)?)
        }
        "docker_containers_list" => {
            let server_ids = parse_server_ids(&args)?;
            let state_filter = match args.get("state").and_then(|v| v.as_str()).unwrap_or("running") {
                "stopped" => DockerContainerStateFilter::Stopped,
                "all" => DockerContainerStateFilter::All,
                _ => DockerContainerStateFilter::Running,
            };
            let limit = opt_u32(&args, "limit").unwrap_or(200).clamp(1, 1000) as usize;
            let sudo = opt_bool(&args, "sudo", false);
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let wait_ms = args
                .get("waitMs")
                .and_then(|v| v.as_u64())
                .unwrap_or(120_000);

            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids,
                    operation: ToolOperation::DockerContainersList {
                        state: state_filter,
                        limit,
                        sudo,
                        timeout_seconds,
                    },
                    requester: Some(requester.to_string()),
                    reason: None,
                })
                .await?;
            let waited = wait_created_job(&state.jobs, &job.id, job.revision, wait_ms).await?;
            Ok(serde_json::to_value(waited)?)
        }
        "docker_container_stats" => {
            let server_ids = parse_server_ids(&args)?;
            let containers: Vec<String> = args
                .get("containers")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(ToString::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let sudo = opt_bool(&args, "sudo", false);
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let wait_ms = args
                .get("waitMs")
                .and_then(|v| v.as_u64())
                .unwrap_or(120_000);

            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids,
                    operation: ToolOperation::DockerContainerStats {
                        containers,
                        sudo,
                        timeout_seconds,
                    },
                    requester: Some(requester.to_string()),
                    reason: None,
                })
                .await?;
            let waited = wait_created_job(&state.jobs, &job.id, job.revision, wait_ms).await?;
            Ok(serde_json::to_value(waited)?)
        }
        "docker_disk_usage" => {
            let server_ids = parse_server_ids(&args)?;
            let sudo = opt_bool(&args, "sudo", false);
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let wait_ms = args
                .get("waitMs")
                .and_then(|v| v.as_u64())
                .unwrap_or(120_000);

            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids,
                    operation: ToolOperation::DockerDiskUsage {
                        sudo,
                        timeout_seconds,
                    },
                    requester: Some(requester.to_string()),
                    reason: None,
                })
                .await?;
            let waited = wait_created_job(&state.jobs, &job.id, job.revision, wait_ms).await?;
            Ok(serde_json::to_value(waited)?)
        }
        "docker_cleanup_preview" => {
            let server_id = req_str(&args, "serverId")?;
            let sudo = opt_bool(&args, "sudo", false);
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let wait_ms = args
                .get("waitMs")
                .and_then(|v| v.as_u64())
                .unwrap_or(120_000);

            let policy: DockerCleanupPolicy = serde_json::from_value(json!({
                "resourceTypes": args.get("resourceTypes").cloned().unwrap_or_else(|| json!(["containers", "images", "buildCache"])),
                "olderThanHours": args.get("olderThanHours").cloned().unwrap_or_else(|| json!(168)),
                "buildCacheKeepUsedWithinHours": args.get("buildCacheKeepUsedWithinHours").cloned().unwrap_or(Value::Null),
                "imageRepository": args.get("imageRepository").cloned().unwrap_or(Value::Null),
                "keepLatestTags": args.get("keepLatestTags").cloned().unwrap_or(Value::Null),
                "includeVolumes": args.get("includeVolumes").cloned().unwrap_or_else(|| json!(false)),
            }))?;

            let job = state
                .jobs
                .create(JobCreateRequest {
                    server_ids: vec![server_id],
                    operation: ToolOperation::DockerCleanupPreview {
                        policy,
                        sudo,
                        timeout_seconds,
                    },
                    requester: Some(requester.to_string()),
                    reason: None,
                })
                .await?;
            let waited = wait_created_job(&state.jobs, &job.id, job.revision, wait_ms).await?;
            Ok(serde_json::to_value(waited)?)
        }
        "docker_cleanup_execute" => {
            let cleanup_plan_id = req_str(&args, "cleanupPlanId")?;
            let timeout_seconds = opt_u32(&args, "timeoutSeconds");
            let reason = opt_str(&args, "reason");
            let wait_ms = args
                .get("waitMs")
                .and_then(|v| v.as_u64())
                .unwrap_or(120_000);

            let job = state
                .jobs
                .create_cleanup_execution(
                    cleanup_plan_id,
                    timeout_seconds,
                    Some(requester.to_string()),
                    reason,
                )
                .await?;
            let waited = wait_created_job(&state.jobs, &job.id, job.revision, wait_ms).await?;
            Ok(serde_json::to_value(waited)?)
        }
        other => Err(CoreError::InvalidInput(format!("未知的 MCP 工具: {other}"))),
    }
}

async fn wait_created_job(
    jobs: &JobService,
    job_id: &str,
    after_revision: i64,
    wait_ms: u64,
) -> CoreResult<crate::models::JobWaitResult> {
    jobs.wait(JobWaitRequest {
        job_id: job_id.to_string(),
        after_revision: Some(after_revision),
        wait_ms: wait_ms.min(300_000),
        until: WaitUntilMode::TerminalOrAttention,
    })
    .await
}

fn parse_server_ids(args: &Value) -> CoreResult<Vec<String>> {
    let arr = args
        .get("serverIds")
        .and_then(|v| v.as_array())
        .ok_or_else(|| CoreError::InvalidInput("缺少必填数组参数 serverIds".to_string()))?;
    let ids: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(str::trim))
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    if ids.is_empty() || ids.len() > 50 {
        return Err(CoreError::InvalidInput(
            "serverIds 数量需在 1..50 之间".to_string(),
        ));
    }
    Ok(ids)
}

fn req_str(args: &Value, key: &str) -> CoreResult<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| CoreError::InvalidInput(format!("缺少必填字符串参数 {key}")))
}

fn opt_str(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn opt_u32(args: &Value, key: &str) -> Option<u32> {
    args.get(key).and_then(|v| v.as_u64()).map(|n| n as u32)
}

fn opt_bool(args: &Value, key: &str, default: bool) -> bool {
    args.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

pub fn mcp_tools_catalog() -> Vec<Value> {
    let server_ids_prop = json!({
        "type": "array",
        "items": { "type": "string" },
        "minItems": 1,
        "maxItems": 50,
        "description": "目标服务器 ID 列表"
    });
    let timeout_prop = json!({
        "type": "integer",
        "minimum": 1,
        "maximum": 1800,
        "description": "命令超时秒数"
    });
    let wait_ms_prop = json!({
        "type": "integer",
        "minimum": 0,
        "maximum": 300000,
        "default": 120000,
        "description": "最长等待毫秒数"
    });
    let reason_prop = json!({
        "type": "string",
        "maxLength": 500,
        "description": "本次变更操作的业务原因（将展示在人工审批界面）"
    });

    vec![
        json!({
            "name": "servers_list",
            "description": "列出控制台已配置的服务器、在线状态、实时指标与主机密钥信任状态。",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        }),
        json!({
            "name": "server_check",
            "description": "发起 SSH 连接与主机密钥状态检查任务。",
            "inputSchema": {
                "type": "object",
                "properties": { "serverIds": server_ids_prop },
                "required": ["serverIds"]
            }
        }),
        json!({
            "name": "system_summary",
            "description": "读取服务器主机名、运行时间、负载、内存与磁盘摘要。",
            "inputSchema": {
                "type": "object",
                "properties": { "serverIds": server_ids_prop, "timeoutSeconds": timeout_prop },
                "required": ["serverIds"]
            }
        }),
        json!({
            "name": "processes_list",
            "description": "按 CPU 使用率列出进程。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "serverIds": server_ids_prop,
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 },
                    "timeoutSeconds": timeout_prop
                },
                "required": ["serverIds"]
            }
        }),
        json!({
            "name": "services_list",
            "description": "按状态列出 systemd 服务。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "serverIds": server_ids_prop,
                    "state": { "type": "string", "enum": ["running", "failed", "active", "inactive"], "default": "running" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 100 },
                    "timeoutSeconds": timeout_prop
                },
                "required": ["serverIds"]
            }
        }),
        json!({
            "name": "service_status",
            "description": "读取指定 systemd 服务的详细状态。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "serverIds": server_ids_prop,
                    "service": { "type": "string" },
                    "timeoutSeconds": timeout_prop
                },
                "required": ["serverIds", "service"]
            }
        }),
        json!({
            "name": "service_control",
            "description": "启动、停止、重启或重载 systemd 服务（需审批模式服务器将进入待审批队列）。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "serverIds": server_ids_prop,
                    "service": { "type": "string" },
                    "action": { "type": "string", "enum": ["start", "stop", "restart", "reload"] },
                    "sudo": { "type": "boolean", "default": false },
                    "reason": reason_prop,
                    "timeoutSeconds": timeout_prop
                },
                "required": ["serverIds", "service", "action"]
            }
        }),
        json!({
            "name": "logs_query",
            "description": "查询 journald 系统或服务日志。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "serverIds": server_ids_prop,
                    "unit": { "type": "string" },
                    "lines": { "type": "integer", "minimum": 1, "maximum": 5000, "default": 200 },
                    "since": { "type": "string" },
                    "query": { "type": "string" },
                    "timeoutSeconds": timeout_prop
                },
                "required": ["serverIds"]
            }
        }),
        json!({
            "name": "shell_execute",
            "description": "在目标服务器执行完整 Shell 命令（需审批模式服务器必须经控制台批准后执行）。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "serverIds": server_ids_prop,
                    "command": { "type": "string" },
                    "sudo": { "type": "boolean", "default": false },
                    "reason": reason_prop,
                    "timeoutSeconds": timeout_prop
                },
                "required": ["serverIds", "command"]
            }
        }),
        json!({
            "name": "file_upload",
            "description": "从本机路径通过 SFTP 原子上传文件到远程服务器（创建任务时锁定本机文件快照哈希）。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "serverIds": server_ids_prop,
                    "localPath": { "type": "string" },
                    "remotePath": { "type": "string" },
                    "overwrite": { "type": "boolean", "default": false },
                    "reason": reason_prop,
                    "timeoutSeconds": timeout_prop
                },
                "required": ["serverIds", "localPath", "remotePath"]
            }
        }),
        json!({
            "name": "file_download",
            "description": "通过 SFTP 原子下载远程服务器文件到本机路径。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "serverIds": server_ids_prop,
                    "remotePath": { "type": "string" },
                    "localPath": { "type": "string" },
                    "overwrite": { "type": "boolean", "default": false },
                    "reason": reason_prop,
                    "timeoutSeconds": timeout_prop
                },
                "required": ["serverIds", "remotePath", "localPath"]
            }
        }),
        json!({
            "name": "jobs_list",
            "description": "列出最近的持久任务及逐服务器状态。",
            "inputSchema": {
                "type": "object",
                "properties": { "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 30 } }
            }
        }),
        json!({
            "name": "job_get",
            "description": "读取单个任务详情及逐目标服务器状态。",
            "inputSchema": {
                "type": "object",
                "properties": { "jobId": { "type": "string" } },
                "required": ["jobId"]
            }
        }),
        json!({
            "name": "job_wait",
            "description": "长轮询等待既有任务完成、进入待审批或 revision 变化，绝不会创建重复任务。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "jobId": { "type": "string" },
                    "afterRevision": { "type": "integer" },
                    "waitMs": wait_ms_prop,
                    "until": { "type": "string", "enum": ["terminal_or_attention", "change"], "default": "terminal_or_attention" }
                },
                "required": ["jobId"]
            }
        }),
        json!({
            "name": "job_output_read",
            "description": "按 UTF-8 安全字节分页读取某个任务目标的标准输出与错误日志。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "jobId": { "type": "string" },
                    "targetId": { "type": "string" },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 },
                    "cursor": { "type": "string" },
                    "limitBytes": { "type": "integer", "minimum": 1, "maximum": 65536, "default": 65536 }
                },
                "required": ["jobId", "targetId"]
            }
        }),
        json!({
            "name": "job_cancel",
            "description": "取消排队中、等待审批或正在执行的任务。",
            "inputSchema": {
                "type": "object",
                "properties": { "jobId": { "type": "string" } },
                "required": ["jobId"]
            }
        }),
        json!({
            "name": "docker_containers_list",
            "description": "结构化列出 Docker 容器（名称、镜像、状态、健康检查、端口、大小）。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "serverIds": server_ids_prop,
                    "state": { "type": "string", "enum": ["running", "stopped", "all"], "default": "running" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000, "default": 200 },
                    "sudo": { "type": "boolean", "default": false },
                    "timeoutSeconds": timeout_prop,
                    "waitMs": wait_ms_prop
                },
                "required": ["serverIds"]
            }
        }),
        json!({
            "name": "docker_container_stats",
            "description": "结构化读取 Docker 容器实时 CPU、内存、网络 I/O、磁盘 I/O 与 PID 数。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "serverIds": server_ids_prop,
                    "containers": { "type": "array", "items": { "type": "string" }, "default": [] },
                    "sudo": { "type": "boolean", "default": false },
                    "timeoutSeconds": timeout_prop,
                    "waitMs": wait_ms_prop
                },
                "required": ["serverIds"]
            }
        }),
        json!({
            "name": "docker_disk_usage",
            "description": "结构化读取 Docker 镜像、容器、数据卷与构建缓存的空间占用及可回收量。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "serverIds": server_ids_prop,
                    "sudo": { "type": "boolean", "default": false },
                    "timeoutSeconds": timeout_prop,
                    "waitMs": wait_ms_prop
                },
                "required": ["serverIds"]
            }
        }),
        json!({
            "name": "docker_cleanup_preview",
            "description": "只读生成 15 分钟有效的 Docker 安全清理预览计划（明确列出目标、受保护资源与风险提示，绝不删除任何对象）。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "serverId": { "type": "string" },
                    "resourceTypes": {
                        "type": "array",
                        "items": { "type": "string", "enum": ["containers", "images", "volumes", "buildCache"] },
                        "default": ["containers", "images", "buildCache"]
                    },
                    "olderThanHours": { "type": "integer", "minimum": 1, "maximum": 8760, "default": 168 },
                    "buildCacheKeepUsedWithinHours": { "type": "integer", "minimum": 1, "maximum": 8760 },
                    "imageRepository": { "type": "string" },
                    "keepLatestTags": { "type": "integer", "minimum": 1, "maximum": 100 },
                    "includeVolumes": { "type": "boolean", "default": false },
                    "sudo": { "type": "boolean", "default": false },
                    "timeoutSeconds": timeout_prop,
                    "waitMs": wait_ms_prop
                },
                "required": ["serverId"]
            }
        }),
        json!({
            "name": "docker_cleanup_execute",
            "description": "执行由 docker_cleanup_preview 生成的单次清理计划（执行前二次复验对象摘要，包含卷删除时无论何种模式均强制独立人工审批）。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cleanupPlanId": { "type": "string" },
                    "reason": reason_prop,
                    "timeoutSeconds": timeout_prop,
                    "waitMs": wait_ms_prop
                },
                "required": ["cleanupPlanId"]
            }
        }),
    ]
}
