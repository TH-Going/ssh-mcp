use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DockerResourceType {
    #[serde(rename = "containers")]
    Containers,
    #[serde(rename = "images")]
    Images,
    #[serde(rename = "volumes")]
    Volumes,
    #[serde(rename = "buildCache")]
    BuildCache,
}

impl DockerResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Containers => "containers",
            Self::Images => "images",
            Self::Volumes => "volumes",
            Self::BuildCache => "buildCache",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerContainerStateFilter {
    Running,
    Stopped,
    All,
}

impl Default for DockerContainerStateFilter {
    fn default() -> Self {
        Self::Running
    }
}

impl DockerContainerStateFilter {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::All => "all",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerCleanupPolicy {
    #[serde(default = "default_cleanup_resources")]
    pub resource_types: Vec<DockerResourceType>,
    #[serde(default = "default_older_than_hours")]
    pub older_than_hours: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_cache_keep_used_within_hours: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_repository: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_latest_tags: Option<usize>,
    #[serde(default)]
    pub include_volumes: bool,
}

fn default_cleanup_resources() -> Vec<DockerResourceType> {
    vec![
        DockerResourceType::Containers,
        DockerResourceType::Images,
        DockerResourceType::BuildCache,
    ]
}

fn default_older_than_hours() -> u32 {
    168
}

impl DockerCleanupPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.resource_types.is_empty() {
            return Err("resourceTypes 不能为空".to_string());
        }
        if self.older_than_hours == 0 || self.older_than_hours > 8760 {
            return Err("olderThanHours 必须在 1..8760 之间".to_string());
        }
        if self.resource_types.contains(&DockerResourceType::Volumes) && !self.include_volumes {
            return Err("包含 volumes 清理时必须显式设置 includeVolumes = true".to_string());
        }
        if self.keep_latest_tags.is_some() && self.image_repository.as_deref().unwrap_or("").is_empty() {
            return Err("设置 keepLatestTags 时必须同时指定 imageRepository".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerContainerEntry {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub health: String,
    pub ports: String,
    pub created_at: String,
    pub size_bytes: u64,
    pub root_fs_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerContainersListResult {
    pub state: String,
    pub containers: Vec<DockerContainerEntry>,
    pub total: usize,
    pub returned: usize,
    pub truncated: bool,
    pub collected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerMemoryStat {
    pub usage_bytes: u64,
    pub limit_bytes: u64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerNetStat {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerBlockIoStat {
    pub read_bytes: u64,
    pub write_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerContainerStatEntry {
    pub id: String,
    pub name: String,
    pub cpu_percent: f64,
    pub memory: DockerMemoryStat,
    pub network: DockerNetStat,
    pub block_io: DockerBlockIoStat,
    pub pids: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerContainerStatsResult {
    pub containers: Vec<DockerContainerStatEntry>,
    pub collected_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerUsageBucket {
    pub total: u64,
    pub active: u64,
    pub size_bytes: u64,
    pub reclaimable_bytes: u64,
    pub reclaimable_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerDiskUsageResult {
    pub images: DockerUsageBucket,
    pub containers: DockerUsageBucket,
    pub volumes: DockerUsageBucket,
    pub build_cache: DockerUsageBucket,
    pub collected_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerCleanupAction {
    RemoveContainer,
    RemoveImage,
    RemoveVolume,
    PruneBuildCacheId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerCleanupTarget {
    pub resource_type: DockerResourceType,
    pub stable_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_image_id: Option<String>,
    pub display_name: String,
    pub size_bytes: u64,
    pub estimated_reclaimable_bytes: u64,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
    pub action: DockerCleanupAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerProtectedResource {
    pub resource_type: DockerResourceType,
    pub stable_id: String,
    pub reason_code: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerRiskWarning {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerCleanupPreviewResult {
    pub cleanup_plan_id: String,
    pub server_id: String,
    pub generated_at: String,
    pub expires_at: String,
    pub policy: DockerCleanupPolicy,
    pub policy_summary: String,
    pub target_digest: String,
    pub targets: Vec<DockerCleanupTarget>,
    pub protected_resources: Vec<DockerProtectedResource>,
    pub estimated_reclaimable_bytes: u64,
    pub estimate_confidence: String,
    pub risk_warnings: Vec<DockerRiskWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerContainerHealthSummary {
    pub id: String,
    pub name: String,
    pub health: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerCleanupVerification {
    pub completed: bool,
    pub error: Option<String>,
    pub running_containers_before: Vec<String>,
    pub running_containers_after: Vec<String>,
    pub running_containers_unchanged: bool,
    pub container_health_after: Vec<DockerContainerHealthSummary>,
    pub retained_repository_tags: Vec<String>,
    pub keep_latest_satisfied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerCleanupFailedItem {
    pub target: DockerCleanupTarget,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerCleanupExecutionResult {
    pub cleanup_plan_id: String,
    pub before: DockerDiskUsageResult,
    pub after: Option<DockerDiskUsageResult>,
    pub freed_bytes: Option<i64>,
    pub deleted: Vec<DockerCleanupTarget>,
    pub failed: Vec<DockerCleanupFailedItem>,
    pub verification: DockerCleanupVerification,
    pub warnings: Vec<String>,
}
