use serde::{Deserialize, Serialize};

use super::approvals::ApprovalRiskLevel;
use super::docker::{DockerCleanupPolicy, DockerContainerStateFilter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStateFilter {
    Running,
    Failed,
    Active,
    Inactive,
}

impl Default for ServiceStateFilter {
    fn default() -> Self {
        Self::Running
    }
}

impl ServiceStateFilter {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Failed => "failed",
            Self::Active => "active",
            Self::Inactive => "inactive",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceControlAction {
    Start,
    Stop,
    Restart,
    Reload,
}

impl ServiceControlAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Reload => "reload",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "tool", rename_all = "snake_case")]
pub enum ToolOperation {
    ServerCheck,
    #[serde(rename_all = "camelCase")]
    SystemSummary {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
    },
    #[serde(rename_all = "camelCase")]
    ProcessesList {
        #[serde(default = "default_processes_limit")]
        limit: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
    },
    #[serde(rename_all = "camelCase")]
    ServicesList {
        #[serde(default)]
        state: ServiceStateFilter,
        #[serde(default = "default_services_limit")]
        limit: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
    },
    #[serde(rename_all = "camelCase")]
    ServiceStatus {
        service: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
    },
    #[serde(rename_all = "camelCase")]
    ServiceControl {
        service: String,
        action: ServiceControlAction,
        #[serde(default)]
        sudo: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    LogsQuery {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unit: Option<String>,
        #[serde(default = "default_logs_lines")]
        lines: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
    },
    #[serde(rename_all = "camelCase")]
    ShellExecute {
        command: String,
        #[serde(default)]
        sudo: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    FileUpload {
        local_path: String,
        remote_path: String,
        #[serde(default)]
        overwrite: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    FileDownload {
        remote_path: String,
        local_path: String,
        #[serde(default)]
        overwrite: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    DockerContainersList {
        #[serde(default)]
        state: DockerContainerStateFilter,
        #[serde(default = "default_docker_containers_limit")]
        limit: usize,
        #[serde(default)]
        sudo: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
    },
    #[serde(rename_all = "camelCase")]
    DockerContainerStats {
        #[serde(default)]
        containers: Vec<String>,
        #[serde(default)]
        sudo: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
    },
    #[serde(rename_all = "camelCase")]
    DockerDiskUsage {
        #[serde(default)]
        sudo: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
    },
    #[serde(rename_all = "camelCase")]
    DockerCleanupPreview {
        policy: DockerCleanupPolicy,
        #[serde(default)]
        sudo: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
    },
    #[serde(rename_all = "camelCase")]
    DockerCleanupExecute {
        cleanup_plan_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_seconds: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

fn default_processes_limit() -> u32 {
    50
}
fn default_services_limit() -> u32 {
    100
}
fn default_logs_lines() -> u32 {
    200
}
fn default_docker_containers_limit() -> usize {
    200
}

impl ToolOperation {
    pub fn tool_name(&self) -> &'static str {
        match self {
            Self::ServerCheck => "server_check",
            Self::SystemSummary { .. } => "system_summary",
            Self::ProcessesList { .. } => "processes_list",
            Self::ServicesList { .. } => "services_list",
            Self::ServiceStatus { .. } => "service_status",
            Self::ServiceControl { .. } => "service_control",
            Self::LogsQuery { .. } => "logs_query",
            Self::ShellExecute { .. } => "shell_execute",
            Self::FileUpload { .. } => "file_upload",
            Self::FileDownload { .. } => "file_download",
            Self::DockerContainersList { .. } => "docker_containers_list",
            Self::DockerContainerStats { .. } => "docker_container_stats",
            Self::DockerDiskUsage { .. } => "docker_disk_usage",
            Self::DockerCleanupPreview { .. } => "docker_cleanup_preview",
            Self::DockerCleanupExecute { .. } => "docker_cleanup_execute",
        }
    }

    pub fn display_label(&self) -> &'static str {
        match self {
            Self::ServerCheck => "连接检查",
            Self::SystemSummary { .. } => "系统摘要",
            Self::ProcessesList { .. } => "进程列表",
            Self::ServicesList { .. } => "服务列表",
            Self::ServiceStatus { .. } => "服务状态",
            Self::ServiceControl { .. } => "服务控制",
            Self::LogsQuery { .. } => "日志查询",
            Self::ShellExecute { .. } => "Shell 命令",
            Self::FileUpload { .. } => "上传文件",
            Self::FileDownload { .. } => "下载文件",
            Self::DockerContainersList { .. } => "Docker 容器",
            Self::DockerContainerStats { .. } => "Docker 资源统计",
            Self::DockerDiskUsage { .. } => "Docker 磁盘分析",
            Self::DockerCleanupPreview { .. } => "Docker 清理预览",
            Self::DockerCleanupExecute { .. } => "Docker 清理执行",
        }
    }

    pub fn is_read_only_tool(&self) -> bool {
        matches!(
            self,
            Self::ServerCheck
                | Self::SystemSummary { .. }
                | Self::ProcessesList { .. }
                | Self::ServicesList { .. }
                | Self::ServiceStatus { .. }
                | Self::LogsQuery { .. }
                | Self::DockerContainersList { .. }
                | Self::DockerContainerStats { .. }
                | Self::DockerDiskUsage { .. }
                | Self::DockerCleanupPreview { .. }
        )
    }

    pub fn uses_sudo(&self) -> bool {
        match self {
            Self::ServiceControl { sudo, .. }
            | Self::ShellExecute { sudo, .. }
            | Self::DockerContainersList { sudo, .. }
            | Self::DockerContainerStats { sudo, .. }
            | Self::DockerDiskUsage { sudo, .. }
            | Self::DockerCleanupPreview { sudo, .. } => *sudo,
            _ => false,
        }
    }

    pub fn timeout_seconds(&self) -> Option<u32> {
        match self {
            Self::ServerCheck => None,
            Self::SystemSummary { timeout_seconds }
            | Self::ProcessesList { timeout_seconds, .. }
            | Self::ServicesList { timeout_seconds, .. }
            | Self::ServiceStatus { timeout_seconds, .. }
            | Self::ServiceControl { timeout_seconds, .. }
            | Self::LogsQuery { timeout_seconds, .. }
            | Self::ShellExecute { timeout_seconds, .. }
            | Self::FileUpload { timeout_seconds, .. }
            | Self::FileDownload { timeout_seconds, .. }
            | Self::DockerContainersList { timeout_seconds, .. }
            | Self::DockerContainerStats { timeout_seconds, .. }
            | Self::DockerDiskUsage { timeout_seconds, .. }
            | Self::DockerCleanupPreview { timeout_seconds, .. }
            | Self::DockerCleanupExecute { timeout_seconds, .. } => *timeout_seconds,
        }
    }

    pub fn caller_reason(&self) -> Option<&str> {
        match self {
            Self::ServiceControl { reason, .. }
            | Self::ShellExecute { reason, .. }
            | Self::FileUpload { reason, .. }
            | Self::FileDownload { reason, .. }
            | Self::DockerCleanupExecute { reason, .. } => reason.as_deref(),
            _ => None,
        }
    }

    pub fn command_preview(&self) -> String {
        match self {
            Self::ServerCheck => "ssh handshake check".to_string(),
            Self::SystemSummary { .. } => "hostname && uptime -p && free -b && df -B1".to_string(),
            Self::ProcessesList { limit, .. } => {
                format!("ps -eo pid,user,pcpu,pmem,etime,comm,args --sort=-pcpu | head -n {}", limit + 1)
            }
            Self::ServicesList { state, limit, .. } => {
                format!(
                    "systemctl list-units --type=service --state={} | head -n {}",
                    state.as_str(),
                    limit
                )
            }
            Self::ServiceStatus { service, .. } => format!("systemctl status {}", service),
            Self::ServiceControl {
                service,
                action,
                sudo,
                ..
            } => {
                let prefix = if *sudo { "sudo " } else { "" };
                format!("{}systemctl {} {}", prefix, action.as_str(), service)
            }
            Self::LogsQuery {
                unit,
                lines,
                since,
                query,
                ..
            } => {
                let mut s = format!("journalctl -n {}", lines);
                if let Some(u) = unit {
                    s.push_str(&format!(" -u {}", u));
                }
                if let Some(si) = since {
                    s.push_str(&format!(" --since '{}'", si));
                }
                if let Some(q) = query {
                    s.push_str(&format!(" --grep '{}'", q));
                }
                s
            }
            Self::ShellExecute { command, sudo, .. } => {
                if *sudo {
                    format!("sudo -- sh -c '{}'", command)
                } else {
                    command.clone()
                }
            }
            Self::FileUpload {
                local_path,
                remote_path,
                overwrite,
                ..
            } => {
                format!(
                    "sftp upload {} -> {}{}",
                    local_path,
                    remote_path,
                    if *overwrite { " (overwrite)" } else { "" }
                )
            }
            Self::FileDownload {
                remote_path,
                local_path,
                overwrite,
                ..
            } => {
                format!(
                    "sftp download {} -> {}{}",
                    remote_path,
                    local_path,
                    if *overwrite { " (overwrite)" } else { "" }
                )
            }
            Self::DockerContainersList { state, limit, .. } => {
                format!("docker container ls ({}, limit {})", state.as_str(), limit)
            }
            Self::DockerContainerStats { containers, .. } => {
                if containers.is_empty() {
                    "docker container stats --no-stream".to_string()
                } else {
                    format!("docker container stats --no-stream {}", containers.join(" "))
                }
            }
            Self::DockerDiskUsage { .. } => "docker system df".to_string(),
            Self::DockerCleanupPreview { .. } => "docker cleanup preview (read-only inventory)".to_string(),
            Self::DockerCleanupExecute { cleanup_plan_id, .. } => {
                format!("docker cleanup execute (plan {})", cleanup_plan_id)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    WaitingApproval,
    Running,
    Succeeded,
    PartialFailure,
    Failed,
    Cancelled,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::WaitingApproval => "waiting_approval",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::PartialFailure => "partial_failure",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn from_db(s: &str) -> Self {
        match s {
            "queued" => Self::Queued,
            "waiting_approval" => Self::WaitingApproval,
            "running" => Self::Running,
            "succeeded" => Self::Succeeded,
            "partial_failure" => Self::PartialFailure,
            "cancelled" => Self::Cancelled,
            _ => Self::Failed,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Queued | Self::WaitingApproval | Self::Running)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetStatus {
    Queued,
    WaitingApproval,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

impl TargetStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::WaitingApproval => "waiting_approval",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn from_db(s: &str) -> Self {
        match s {
            "queued" => Self::Queued,
            "waiting_approval" => Self::WaitingApproval,
            "running" => Self::Running,
            "succeeded" => Self::Succeeded,
            "cancelled" => Self::Cancelled,
            _ => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobTarget {
    pub id: String,
    pub server_id: String,
    pub server_name: String,
    pub status: TargetStatus,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub output_bytes: u64,
    pub output_truncated: bool,
    pub executed_command: Option<String>,
    pub structured_result: Option<serde_json::Value>,
    pub approval_id: Option<String>,
    pub approval_reason: Option<String>,
    pub matched_policy: Option<String>,
    pub risk_level: Option<ApprovalRiskLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub id: String,
    pub tool: String,
    pub tool_label: String,
    pub requester: String,
    pub reason: Option<String>,
    pub operation: ToolOperation,
    pub status: JobStatus,
    pub targets: Vec<JobTarget>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub revision: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobCreateRequest {
    pub server_ids: Vec<String>,
    pub operation: ToolOperation,
    #[serde(default)]
    pub requester: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobOutputSummary {
    pub returned_bytes: usize,
    pub line_count: usize,
    pub has_stdout: bool,
    pub has_stderr: bool,
    pub has_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobOutput {
    pub target_id: String,
    pub content: String,
    pub offset: u64,
    pub next_offset: Option<u64>,
    pub total_bytes: u64,
    pub expires_at: String,
    pub cursor: String,
    pub next_cursor: Option<String>,
    pub truncated: bool,
    pub summary: JobOutputSummary,
    pub page_summary: JobOutputSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitUntilMode {
    TerminalOrAttention,
    Change,
}

impl Default for WaitUntilMode {
    fn default() -> Self {
        Self::TerminalOrAttention
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobWaitRequest {
    pub job_id: String,
    #[serde(default)]
    pub after_revision: Option<i64>,
    #[serde(default = "default_wait_ms")]
    pub wait_ms: u64,
    #[serde(default)]
    pub until: WaitUntilMode,
}

fn default_wait_ms() -> u64 {
    120_000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeReason {
    Terminal,
    WaitingApproval,
    Changed,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobWaitResult {
    pub job_id: String,
    pub revision: i64,
    pub changed: bool,
    pub timed_out: bool,
    pub wake_reason: WakeReason,
    pub job: Option<Job>,
}
