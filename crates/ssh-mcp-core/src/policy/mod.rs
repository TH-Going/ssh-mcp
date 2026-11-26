use std::sync::LazyLock;

use regex::Regex;

use crate::models::{ApprovalRiskLevel, ControlMode, Server, ToolOperation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationCategory {
    Read,
    Write,
    Delete,
    ServiceControl,
    Sudo,
    ArbitraryShell,
}

impl OperationCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::ServiceControl => "service_control",
            Self::Sudo => "sudo",
            Self::ArbitraryShell => "arbitrary_shell",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApprovalPolicyContext {
    pub allow_read_only_shell_without_approval: bool,
    pub cleanup_includes_volumes: bool,
    pub policy_summary: Option<String>,
}

impl Default for ApprovalPolicyContext {
    fn default() -> Self {
        Self {
            allow_read_only_shell_without_approval: false,
            cleanup_includes_volumes: false,
            policy_summary: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApprovalPolicyDecision {
    pub requires_approval: bool,
    pub approval_reason: String,
    pub matched_policy: String,
    pub risk_level: ApprovalRiskLevel,
    pub category: OperationCategory,
    pub policy_summary: Option<String>,
}

const READ_ONLY_EXECUTABLES: &[&str] = &[
    "/bin/df",
    "/bin/free",
    "/bin/uname",
    "/usr/bin/df",
    "/usr/bin/free",
    "/usr/bin/id",
    "/usr/bin/uname",
    "/usr/bin/uptime",
    "/usr/bin/whoami",
];

static SHELL_META_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[;&|`$><\\\r\n*?\[\]{}()\x22\x27]").unwrap());
static SAFE_ARG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_./:@%+=,-]+$").unwrap());
static DELETE_SHELL_1_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:sudo\s+)?(?:rm|rmdir|unlink|shred)\b").unwrap());
static DELETE_SHELL_2_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:sudo\s+)?docker\s+\S+\s+(?:rm|remove|prune)\b").unwrap());
static SERVICE_SHELL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:sudo\s+)?systemctl\s+(?:start|stop|restart|reload|enable|disable|mask|unmask)\b")
        .unwrap()
});
static WRITE_SHELL_1_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:sudo\s+)?(?:cp|mv|touch|mkdir|chmod|chown|ln|truncate|tee)\b").unwrap()
});
static WRITE_SHELL_2_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:sudo\s+)?sed\s+[^\r\n]*\s-i(?:\s|$)").unwrap());

pub fn evaluate_approval_policy(
    server: &Server,
    operation: &ToolOperation,
    ctx: &ApprovalPolicyContext,
) -> ApprovalPolicyDecision {
    if matches!(operation, ToolOperation::DockerCleanupExecute { .. }) && ctx.cleanup_includes_volumes {
        return make_decision(
            true,
            "清理计划包含未使用卷删除，卷删除必须显式启用并独立审批",
            "docker.cleanup.volume_delete",
            ApprovalRiskLevel::High,
            OperationCategory::Delete,
            ctx.policy_summary.clone(),
        );
    }

    let classified = classify_operation(
        operation,
        ctx.allow_read_only_shell_without_approval,
        ctx.policy_summary.clone(),
    );

    if server.control_mode == ControlMode::Direct {
        return ApprovalPolicyDecision {
            requires_approval: false,
            approval_reason: format!(
                "服务器为全自动模式；操作仍按 {} 风险审计",
                classified.category.as_str()
            ),
            matched_policy: format!("server.direct.{}", classified.matched_policy),
            ..classified
        };
    }

    classified
}

pub fn is_recognized_read_only_shell(command: &str) -> bool {
    let trimmed = command.trim();
    if trimmed.is_empty() || SHELL_META_RE.is_match(trimmed) {
        return false;
    }
    let tokens: Vec<&str> = trimmed.split([' ', '\t']).filter(|s| !s.is_empty()).collect();
    if tokens.is_empty() || tokens.iter().any(|t| !SAFE_ARG_RE.is_match(t)) {
        return false;
    }
    READ_ONLY_EXECUTABLES.contains(&tokens[0])
}

fn classify_operation(
    operation: &ToolOperation,
    allow_read_only_shell: bool,
    policy_summary: Option<String>,
) -> ApprovalPolicyDecision {
    if operation.uses_sudo() {
        return make_decision(
            true,
            "操作请求 sudo 提权，必须人工审批",
            "operation.sudo",
            ApprovalRiskLevel::High,
            OperationCategory::Sudo,
            policy_summary,
        );
    }

    match operation {
        ToolOperation::ShellExecute { command, .. } => {
            if is_recognized_read_only_shell(command) {
                if allow_read_only_shell {
                    make_decision(
                        false,
                        "命令命中严格只读 Shell 白名单，且策略已允许免审批",
                        "shell.read_only.exempt",
                        ApprovalRiskLevel::Low,
                        OperationCategory::Read,
                        policy_summary,
                    )
                } else {
                    make_decision(
                        true,
                        "命令已识别为纯只读，但当前策略未开启只读 Shell 免审批",
                        "shell.read_only.default_approval",
                        ApprovalRiskLevel::High,
                        OperationCategory::Read,
                        policy_summary,
                    )
                }
            } else if DELETE_SHELL_1_RE.is_match(command) || DELETE_SHELL_2_RE.is_match(command) {
                make_decision(
                    true,
                    "Shell 命令包含删除语义，必须人工审批",
                    "shell.delete",
                    ApprovalRiskLevel::High,
                    OperationCategory::Delete,
                    policy_summary,
                )
            } else if SERVICE_SHELL_RE.is_match(command) {
                make_decision(
                    true,
                    "Shell 命令包含服务控制语义，必须人工审批",
                    "shell.service_control",
                    ApprovalRiskLevel::High,
                    OperationCategory::ServiceControl,
                    policy_summary,
                )
            } else if WRITE_SHELL_1_RE.is_match(command) || WRITE_SHELL_2_RE.is_match(command) {
                make_decision(
                    true,
                    "Shell 命令包含写入语义，必须人工审批",
                    "shell.write",
                    ApprovalRiskLevel::High,
                    OperationCategory::Write,
                    policy_summary,
                )
            } else {
                make_decision(
                    true,
                    "任意 Shell 无法证明为纯只读，必须人工审批",
                    "shell.arbitrary",
                    ApprovalRiskLevel::High,
                    OperationCategory::ArbitraryShell,
                    policy_summary,
                )
            }
        }
        ToolOperation::ServiceControl { .. } => make_decision(
            true,
            "systemd 服务控制会改变远端状态，必须人工审批",
            "tool.service_control",
            ApprovalRiskLevel::Medium,
            OperationCategory::ServiceControl,
            policy_summary,
        ),
        ToolOperation::DockerCleanupExecute { .. } => make_decision(
            true,
            "Docker 清理会删除预览计划中的对象，必须人工审批",
            "docker.cleanup.delete",
            ApprovalRiskLevel::High,
            OperationCategory::Delete,
            policy_summary,
        ),
        ToolOperation::FileUpload { .. } | ToolOperation::FileDownload { .. } => make_decision(
            true,
            "文件传输会写入远端或本机文件，必须人工审批",
            "tool.file_write",
            ApprovalRiskLevel::Medium,
            OperationCategory::Write,
            policy_summary,
        ),
        other if other.is_read_only_tool() => make_decision(
            false,
            "专用工具只读取受限范围内的状态",
            "tool.read_only",
            ApprovalRiskLevel::Low,
            OperationCategory::Read,
            policy_summary,
        ),
        _ => make_decision(
            true,
            "操作会改变状态，必须人工审批",
            "tool.write",
            ApprovalRiskLevel::Medium,
            OperationCategory::Write,
            policy_summary,
        ),
    }
}

fn make_decision(
    requires_approval: bool,
    approval_reason: impl Into<String>,
    matched_policy: &str,
    risk_level: ApprovalRiskLevel,
    category: OperationCategory,
    policy_summary: Option<String>,
) -> ApprovalPolicyDecision {
    ApprovalPolicyDecision {
        requires_approval,
        approval_reason: approval_reason.into(),
        matched_policy: matched_policy.to_string(),
        risk_level,
        category,
        policy_summary,
    }
}
