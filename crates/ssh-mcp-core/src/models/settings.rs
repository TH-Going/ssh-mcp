use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub mcp_enabled: bool,
    pub mcp_running: bool,
    pub mcp_port: u16,
    pub mcp_http_endpoint: String,
    pub mcp_stdio_command: String,
    pub refresh_interval_seconds: u32,
    pub failure_alerts_enabled: bool,
    pub autostart_enabled: bool,
    pub default_concurrency: usize,
    pub default_timeout_seconds: u32,
    pub allow_read_only_shell_without_approval: bool,
    pub approval_ttl_seconds: u64,
    pub output_retention_hours: u64,
    pub audit_retention_days: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsUpdateRequest {
    pub mcp_enabled: Option<bool>,
    pub refresh_interval_seconds: Option<u32>,
    pub failure_alerts_enabled: Option<bool>,
    pub autostart_enabled: Option<bool>,
    pub default_concurrency: Option<usize>,
    pub default_timeout_seconds: Option<u32>,
    pub allow_read_only_shell_without_approval: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupPreflightItem {
    pub source_id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub conflict: bool,
    pub existing_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupPreflight {
    pub import_id: String,
    pub version: u32,
    pub servers: Vec<BackupPreflightItem>,
    pub expires_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupImportAction {
    CreateNew,
    Overwrite,
    Skip,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupApplyDecision {
    pub source_id: String,
    pub action: BackupImportAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupApplyResult {
    pub created: usize,
    pub overwritten: usize,
    pub skipped: usize,
}
