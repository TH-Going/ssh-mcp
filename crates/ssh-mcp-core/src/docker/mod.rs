use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{CoreError, CoreResult};
use crate::models::{
    DockerBlockIoStat, DockerCleanupAction, DockerCleanupExecutionResult, DockerCleanupFailedItem,
    DockerCleanupPolicy, DockerCleanupPreviewResult, DockerCleanupTarget,
    DockerCleanupVerification, DockerContainerEntry, DockerContainerHealthSummary,
    DockerContainerStatEntry, DockerContainerStateFilter, DockerContainerStatsResult,
    DockerContainersListResult, DockerDiskUsageResult, DockerMemoryStat, DockerNetStat,
    DockerProtectedResource, DockerResourceType, DockerRiskWarning, DockerUsageBucket,
    ToolOperation,
};
use crate::security::canonical_request_digest;

const SECTION_MARKER: &str = "__SSC_DOCKER_";

static CONTAINER_ID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-f0-9]{12,64}$").unwrap());
static IMAGE_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:sha256:)?[a-f0-9]{12,64}$").unwrap());
static VOLUME_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$").unwrap());
static CACHE_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$").unwrap());
static SAFE_IMAGE_REF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_./:@+-]*$").unwrap());
static BYTE_SIZE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([0-9]+(?:\.[0-9]+)?)\s*(KiB|MiB|GiB|TiB|kB|KB|MB|GB|TB|B)").unwrap()
});
static VIRTUAL_SIZE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\(virtual\s+([^)]+)\)").unwrap());
static PAREN_PCT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\(([^)]+)\)").unwrap());
static HEALTH_STATUS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\((healthy|unhealthy|health:\s*starting)\)").unwrap());

pub fn quote_posix(input: &str) -> String {
    if input.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", input.replace('\'', "'\\''"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryContainer {
    pub id: String,
    pub name: String,
    pub image_id: String,
    pub created_at: String,
    pub status: String,
    pub health: String,
    pub size_bytes: u64,
    pub root_fs_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryImage {
    pub id: String,
    pub repo_tags: Vec<String>,
    pub created_at: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryVolume {
    pub name: String,
    pub driver: String,
    pub created_at: Option<String>,
    pub unused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryBuildCache {
    pub id: String,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
    pub size_bytes: u64,
    pub reclaimable: bool,
    pub shared: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerInventory {
    pub containers: Vec<InventoryContainer>,
    pub images: Vec<InventoryImage>,
    pub volumes: Vec<InventoryVolume>,
    pub build_cache: Vec<InventoryBuildCache>,
    pub disk_usage: DockerDiskUsageResult,
    pub collected_at: String,
}

#[derive(Debug, Clone)]
pub struct CleanupSelection {
    pub policy: DockerCleanupPolicy,
    pub policy_summary: String,
    pub targets: Vec<DockerCleanupTarget>,
    pub protected_resources: Vec<DockerProtectedResource>,
    pub target_digest: String,
    pub estimated_reclaimable_bytes: u64,
    pub estimate_confidence: String,
    pub risk_warnings: Vec<DockerRiskWarning>,
}

pub fn is_docker_operation(op: &ToolOperation) -> bool {
    op.tool_name().starts_with("docker_")
}

pub fn build_docker_command(op: &ToolOperation) -> CoreResult<String> {
    match op {
        ToolOperation::DockerContainersList { .. } => Ok(format!(
            "docker container ls --all --no-trunc --size --format {}",
            quote_posix("{{json .}}")
        )),
        ToolOperation::DockerContainerStats { containers, .. } => {
            let args = containers
                .iter()
                .map(|c| quote_posix(c))
                .collect::<Vec<_>>()
                .join(" ");
            let suffix = if args.is_empty() {
                String::new()
            } else {
                format!(" {args}")
            };
            Ok(format!(
                "docker container stats --no-stream --format {}{}",
                quote_posix("{{json .}}"),
                suffix
            ))
        }
        ToolOperation::DockerDiskUsage { .. } => Ok(format!(
            "docker system df --format {}",
            quote_posix("{{json .}}")
        )),
        ToolOperation::DockerCleanupPreview { policy, .. } => {
            policy.validate().map_err(CoreError::InvalidInput)?;
            Ok(build_inventory_command(
                policy.resource_types.contains(&DockerResourceType::BuildCache),
            ))
        }
        _ => Err(CoreError::InvalidInput("不支持的 Docker 命令构建".to_string())),
    }
}

pub fn build_delete_command(target: &DockerCleanupTarget) -> CoreResult<String> {
    match target.action {
        DockerCleanupAction::RemoveContainer => {
            let id = assert_identifier(&target.stable_id, &CONTAINER_ID_RE, "容器 ID")?;
            Ok(format!("docker container rm {}", quote_posix(id)))
        }
        DockerCleanupAction::RemoveImage => {
            if !IMAGE_ID_RE.is_match(&target.stable_id) && !is_safe_image_ref(&target.stable_id) {
                return Err(CoreError::InvalidInput("镜像引用格式无效".to_string()));
            }
            let expected = target
                .expected_image_id
                .as_deref()
                .ok_or_else(|| CoreError::InvalidInput("清理镜像缺少 expectedImageId".to_string()))?;
            let norm_expected = normalize_image_id(assert_identifier(expected, &IMAGE_ID_RE, "镜像 ID")?);
            Ok(format!(
                "ssc_actual_image_id=$(docker image inspect --format {} {}) && [ \"$ssc_actual_image_id\" = {} ] || {{ echo 'CLEANUP_PLAN_STALE: image reference changed' >&2; exit 43; }}; docker image rm {}",
                quote_posix("{{.Id}}"),
                quote_posix(&target.stable_id),
                quote_posix(&format!("sha256:{norm_expected}")),
                quote_posix(&target.stable_id)
            ))
        }
        DockerCleanupAction::RemoveVolume => {
            let name = assert_identifier(&target.stable_id, &VOLUME_NAME_RE, "卷名称")?;
            Ok(format!("docker volume rm {}", quote_posix(name)))
        }
        DockerCleanupAction::PruneBuildCacheId => {
            let id = assert_identifier(&target.stable_id, &CACHE_ID_RE, "构建缓存 ID")?;
            Ok(format!(
                "docker buildx prune --force --filter {}",
                quote_posix(&format!("id={id}"))
            ))
        }
    }
}

pub fn parse_docker_result(op: &ToolOperation, stdout: &str) -> CoreResult<Value> {
    match op {
        ToolOperation::DockerContainersList { state, limit, .. } => {
            let res = parse_containers_list(stdout, *state, *limit)?;
            Ok(serde_json::to_value(res)?)
        }
        ToolOperation::DockerContainerStats { .. } => {
            let res = parse_container_stats(stdout)?;
            Ok(serde_json::to_value(res)?)
        }
        ToolOperation::DockerDiskUsage { .. } => {
            let res = parse_disk_usage(stdout)?;
            Ok(serde_json::to_value(res)?)
        }
        ToolOperation::DockerCleanupPreview { .. } => {
            let inv = parse_inventory(stdout)?;
            Ok(serde_json::to_value(inv)?)
        }
        _ => Err(CoreError::InvalidInput("不支持的 Docker 输出解析".to_string())),
    }
}

pub fn build_inventory_command(include_build_cache: bool) -> String {
    let container_tpl = "{\"ID\":{{json .Id}},\"Name\":{{json .Name}},\"ImageID\":{{json .Image}},\"Created\":{{json .Created}},\"Status\":{{json .State.Status}},\"Health\":{{if .State.Health}}{{json .State.Health.Status}}{{else}}\"none\"{{end}},\"SizeRw\":{{json .SizeRw}},\"SizeRootFs\":{{json .SizeRootFs}}}";
    let image_tpl = "{\"ID\":{{json .Id}},\"RepoTags\":{{json .RepoTags}},\"Created\":{{json .Created}},\"Size\":{{json .Size}}}";
    let volume_tpl = "{\"Name\":{{json .Name}},\"Driver\":{{json .Driver}},\"CreatedAt\":{{json .CreatedAt}}}";

    let build_cache_line = if include_build_cache {
        "docker buildx version >/dev/null 2>&1 || { echo 'Docker buildx 不可用，无法安全枚举构建缓存' >&2; exit 42; }; docker buildx du --format=json"
    } else {
        ":"
    };

    [
        "set -eu".to_string(),
        marker("CONTAINERS"),
        "ssc_container_ids=$(docker container ls -aq --no-trunc)".to_string(),
        format!(
            "for id in $ssc_container_ids; do docker container inspect --size --format {} \"$id\"; done",
            quote_posix(container_tpl)
        ),
        marker("IMAGES"),
        "ssc_image_ids=$(docker image ls -aq --no-trunc)".to_string(),
        "ssc_seen_image_ids=' '".to_string(),
        format!(
            "for id in $ssc_image_ids; do case \"$ssc_seen_image_ids\" in *\" $id \"*) continue ;; esac; ssc_seen_image_ids=\"$ssc_seen_image_ids$id \"; docker image inspect --format {} \"$id\"; done",
            quote_posix(image_tpl)
        ),
        marker("VOLUMES"),
        "ssc_volume_names=$(docker volume ls -q)".to_string(),
        format!(
            "for name in $ssc_volume_names; do docker volume inspect --format {} \"$name\"; done",
            quote_posix(volume_tpl)
        ),
        marker("UNUSED_VOLUMES"),
        format!(
            "docker volume ls --filter dangling=true --format {}",
            quote_posix("{{json .Name}}")
        ),
        marker("BUILD_CACHE"),
        build_cache_line.to_string(),
        marker("DISK_USAGE"),
        format!("docker system df --format {}", quote_posix("{{json .}}")),
    ]
    .join("\n")
}

pub fn parse_containers_list(
    stdout: &str,
    state: DockerContainerStateFilter,
    limit: usize,
) -> CoreResult<DockerContainersListResult> {
    let rows = parse_json_lines(stdout)?;
    let mut filtered = Vec::new();
    for val in rows {
        let obj = as_object(&val, "Docker 容器列表")?;
        let item_state = str_field(obj, "State", "");
        let keep = match state {
            DockerContainerStateFilter::All => true,
            DockerContainerStateFilter::Running => item_state == "running",
            DockerContainerStateFilter::Stopped => item_state != "running",
        };
        if keep {
            filtered.push(obj.clone());
        }
    }

    let total = filtered.len();
    let mut containers = Vec::new();
    for obj in filtered.into_iter().take(limit) {
        let (size_bytes, root_fs_size_bytes) = parse_container_size(&str_field(&obj, "Size", "0B"));
        let status = str_field(&obj, "Status", "");
        let raw_health = {
            let direct = str_field(&obj, "HealthStatus", "");
            if !direct.is_empty() {
                direct
            } else {
                HEALTH_STATUS_RE
                    .captures(&status)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_lowercase())
                    .unwrap_or_default()
            }
        };
        let health = match raw_health.as_str() {
            "healthy" => "healthy",
            "unhealthy" => "unhealthy",
            s if s.contains("starting") => "starting",
            _ => "none",
        }
        .to_string();

        containers.push(DockerContainerEntry {
            id: str_field(&obj, "ID", ""),
            name: str_field(&obj, "Names", ""),
            image: str_field(&obj, "Image", ""),
            state: str_field(&obj, "State", ""),
            status,
            health,
            ports: str_field(&obj, "Ports", ""),
            created_at: str_field(&obj, "CreatedAt", ""),
            size_bytes,
            root_fs_size_bytes,
        });
    }

    let returned = containers.len();
    Ok(DockerContainersListResult {
        state: state.as_str().to_string(),
        containers,
        total,
        returned,
        truncated: total > returned,
        collected_at: Utc::now().to_rfc3339(),
    })
}

pub fn parse_container_stats(stdout: &str) -> CoreResult<DockerContainerStatsResult> {
    let rows = parse_json_lines(stdout)?;
    let mut containers = Vec::with_capacity(rows.len());
    for val in rows {
        let obj = as_object(&val, "Docker stats")?;
        let (mem_used, mem_limit) = parse_io_pair(&str_field(obj, "MemUsage", "0B / 0B"));
        let (rx, tx) = parse_io_pair(&str_field(obj, "NetIO", "0B / 0B"));
        let (read_b, write_b) = parse_io_pair(&str_field(obj, "BlockIO", "0B / 0B"));
        let container_fallback = str_field(obj, "Container", "");
        containers.push(DockerContainerStatEntry {
            id: str_field(obj, "ID", &container_fallback),
            name: str_field(obj, "Name", &container_fallback),
            cpu_percent: parse_percent(&str_field(obj, "CPUPerc", "0")),
            memory: DockerMemoryStat {
                usage_bytes: mem_used,
                limit_bytes: mem_limit,
                percent: parse_percent(&str_field(obj, "MemPerc", "0")),
            },
            network: DockerNetStat {
                rx_bytes: rx,
                tx_bytes: tx,
            },
            block_io: DockerBlockIoStat {
                read_bytes: read_b,
                write_bytes: write_b,
            },
            pids: str_field(obj, "PIDs", "0").parse::<u64>().unwrap_or(0),
        });
    }
    Ok(DockerContainerStatsResult {
        containers,
        collected_at: Utc::now().to_rfc3339(),
    })
}

pub fn parse_disk_usage(stdout: &str) -> CoreResult<DockerDiskUsageResult> {
    let mut res = DockerDiskUsageResult {
        images: DockerUsageBucket::default(),
        containers: DockerUsageBucket::default(),
        volumes: DockerUsageBucket::default(),
        build_cache: DockerUsageBucket::default(),
        collected_at: Utc::now().to_rfc3339(),
    };

    for val in parse_json_lines(stdout)? {
        let obj = as_object(&val, "Docker 磁盘统计")?;
        let kind = str_field(obj, "Type", "").to_lowercase();
        let reclaimable_raw = str_field(obj, "Reclaimable", "0B");
        let pct_str = PAREN_PCT_RE
            .captures(&reclaimable_raw)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .unwrap_or("0");
        let bucket = DockerUsageBucket {
            total: int_field(obj, &["TotalCount", "Total"]),
            active: int_field(obj, &["Active"]),
            size_bytes: parse_byte_size(&str_field(obj, "Size", "0B")),
            reclaimable_bytes: parse_byte_size(&reclaimable_raw),
            reclaimable_percent: parse_percent(pct_str),
        };
        if kind.contains("image") {
            res.images = bucket;
        } else if kind.contains("container") {
            res.containers = bucket;
        } else if kind.contains("volume") {
            res.volumes = bucket;
        } else if kind.contains("build") {
            res.build_cache = bucket;
        }
    }
    Ok(res)
}

pub fn parse_inventory(stdout: &str) -> CoreResult<DockerInventory> {
    let sections = split_sections(stdout);
    let mut containers = Vec::new();
    for val in json_section(&sections, "CONTAINERS")? {
        let obj = as_object(&val, "Docker 容器库存")?;
        containers.push(InventoryContainer {
            id: str_field(obj, "ID", ""),
            name: str_field(obj, "Name", "").trim_start_matches('/').to_string(),
            image_id: str_field(obj, "ImageID", ""),
            created_at: str_field(obj, "Created", ""),
            status: str_field(obj, "Status", ""),
            health: str_field(obj, "Health", "none"),
            size_bytes: u64_field(obj, "SizeRw"),
            root_fs_size_bytes: u64_field(obj, "SizeRootFs"),
        });
    }

    let mut images = Vec::new();
    for val in json_section(&sections, "IMAGES")? {
        let obj = as_object(&val, "Docker 镜像库存")?;
        let repo_tags = obj
            .get("RepoTags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();
        images.push(InventoryImage {
            id: str_field(obj, "ID", ""),
            repo_tags,
            created_at: str_field(obj, "Created", ""),
            size_bytes: u64_field(obj, "Size"),
        });
    }

    let unused_volumes: HashSet<String> = json_section(&sections, "UNUSED_VOLUMES")?
        .into_iter()
        .filter_map(|v| v.as_str().map(ToString::to_string))
        .collect();

    let mut volumes = Vec::new();
    for val in json_section(&sections, "VOLUMES")? {
        let obj = as_object(&val, "Docker 卷库存")?;
        let name = str_field(obj, "Name", "");
        let created_at = obj
            .get("CreatedAt")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);
        volumes.push(InventoryVolume {
            unused: unused_volumes.contains(&name),
            name,
            driver: str_field(obj, "Driver", ""),
            created_at,
        });
    }

    let mut build_cache = Vec::new();
    for val in json_section(&sections, "BUILD_CACHE")? {
        let obj = as_object(&val, "Docker 构建缓存库存")?;
        build_cache.push(InventoryBuildCache {
            id: str_field(obj, "ID", ""),
            created_at: obj
                .get("CreatedAt")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(ToString::to_string),
            last_used_at: obj
                .get("LastUsedAt")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(ToString::to_string),
            size_bytes: u64_field(obj, "Size"),
            reclaimable: obj.get("Reclaimable").and_then(|v| v.as_bool()).unwrap_or(false),
            shared: obj.get("Shared").and_then(|v| v.as_bool()).unwrap_or(false),
        });
    }

    let disk_raw = sections
        .get("DISK_USAGE")
        .map(|lines| lines.join("\n"))
        .unwrap_or_default();
    let disk_usage = parse_disk_usage(&disk_raw)?;

    Ok(DockerInventory {
        containers,
        images,
        volumes,
        build_cache,
        disk_usage,
        collected_at: Utc::now().to_rfc3339(),
    })
}

pub fn select_cleanup_targets(
    inventory: &DockerInventory,
    policy: &DockerCleanupPolicy,
    generated_at: DateTime<Utc>,
) -> CoreResult<CleanupSelection> {
    policy.validate().map_err(CoreError::InvalidInput)?;

    let older_cutoff = generated_at - ChronoDuration::hours(policy.older_than_hours as i64);
    let cache_hours = policy
        .build_cache_keep_used_within_hours
        .unwrap_or(policy.older_than_hours);
    let cache_cutoff = generated_at - ChronoDuration::hours(cache_hours as i64);

    let mut targets = Vec::new();
    let mut protected = Vec::new();
    let used_image_ids: HashSet<String> = inventory
        .containers
        .iter()
        .map(|c| normalize_image_id(&c.image_id).to_string())
        .collect();

    if policy.resource_types.contains(&DockerResourceType::Containers) {
        for c in &inventory.containers {
            if !matches!(c.status.as_str(), "created" | "exited" | "dead") {
                protected.push(DockerProtectedResource {
                    resource_type: DockerResourceType::Containers,
                    stable_id: c.id.clone(),
                    reason_code: "RUNNING_CONTAINER".to_string(),
                    reason: "运行、暂停或重启中的容器不会进入清理计划".to_string(),
                });
            } else if !is_at_or_before(&c.created_at, older_cutoff) {
                protected.push(DockerProtectedResource {
                    resource_type: DockerResourceType::Containers,
                    stable_id: c.id.clone(),
                    reason_code: "RECENTLY_CREATED".to_string(),
                    reason: "容器仍在保留时长内".to_string(),
                });
            } else {
                targets.push(DockerCleanupTarget {
                    resource_type: DockerResourceType::Containers,
                    stable_id: assert_identifier(&c.id, &CONTAINER_ID_RE, "容器 ID")?.to_string(),
                    expected_image_id: None,
                    display_name: c.name.clone(),
                    size_bytes: c.size_bytes,
                    estimated_reclaimable_bytes: c.size_bytes,
                    created_at: Some(c.created_at.clone()),
                    last_used_at: None,
                    action: DockerCleanupAction::RemoveContainer,
                });
            }
        }
    }

    if policy.resource_types.contains(&DockerResourceType::Images) {
        select_images(
            &inventory.images,
            &used_image_ids,
            policy,
            older_cutoff,
            &mut targets,
            &mut protected,
        );
    }

    if policy.resource_types.contains(&DockerResourceType::Volumes) {
        for v in &inventory.volumes {
            if !v.unused {
                protected.push(DockerProtectedResource {
                    resource_type: DockerResourceType::Volumes,
                    stable_id: v.name.clone(),
                    reason_code: "VOLUME_IN_USE".to_string(),
                    reason: "已被容器引用的卷禁止删除".to_string(),
                });
            } else if v.created_at.is_none() {
                protected.push(DockerProtectedResource {
                    resource_type: DockerResourceType::Volumes,
                    stable_id: v.name.clone(),
                    reason_code: "CREATED_AT_UNKNOWN".to_string(),
                    reason: "无法确认卷创建时间，按安全策略保留".to_string(),
                });
            } else if !is_at_or_before(v.created_at.as_deref().unwrap_or(""), older_cutoff) {
                protected.push(DockerProtectedResource {
                    resource_type: DockerResourceType::Volumes,
                    stable_id: v.name.clone(),
                    reason_code: "RECENTLY_CREATED".to_string(),
                    reason: "卷仍在保留时长内".to_string(),
                });
            } else {
                targets.push(DockerCleanupTarget {
                    resource_type: DockerResourceType::Volumes,
                    stable_id: assert_identifier(&v.name, &VOLUME_NAME_RE, "卷名称")?.to_string(),
                    expected_image_id: None,
                    display_name: v.name.clone(),
                    size_bytes: 0,
                    estimated_reclaimable_bytes: 0,
                    created_at: v.created_at.clone(),
                    last_used_at: None,
                    action: DockerCleanupAction::RemoveVolume,
                });
            }
        }
    }

    if policy.resource_types.contains(&DockerResourceType::BuildCache) {
        for bc in &inventory.build_cache {
            if !bc.reclaimable {
                protected.push(DockerProtectedResource {
                    resource_type: DockerResourceType::BuildCache,
                    stable_id: bc.id.clone(),
                    reason_code: "CACHE_IN_USE".to_string(),
                    reason: "正在使用或不可回收的构建缓存禁止删除".to_string(),
                });
            } else if bc.last_used_at.is_none() {
                protected.push(DockerProtectedResource {
                    resource_type: DockerResourceType::BuildCache,
                    stable_id: bc.id.clone(),
                    reason_code: "LAST_USED_UNKNOWN".to_string(),
                    reason: "无法确认最近使用时间，按安全策略保留".to_string(),
                });
            } else if !is_at_or_before(bc.last_used_at.as_deref().unwrap_or(""), cache_cutoff) {
                protected.push(DockerProtectedResource {
                    resource_type: DockerResourceType::BuildCache,
                    stable_id: bc.id.clone(),
                    reason_code: "RECENTLY_USED".to_string(),
                    reason: format!("最近 {cache_hours} 小时使用过的构建缓存予以保留"),
                });
            } else {
                targets.push(DockerCleanupTarget {
                    resource_type: DockerResourceType::BuildCache,
                    stable_id: assert_identifier(&bc.id, &CACHE_ID_RE, "构建缓存 ID")?.to_string(),
                    expected_image_id: None,
                    display_name: bc.id.clone(),
                    size_bytes: bc.size_bytes,
                    estimated_reclaimable_bytes: if bc.shared { 0 } else { bc.size_bytes },
                    created_at: bc.created_at.clone(),
                    last_used_at: bc.last_used_at.clone(),
                    action: DockerCleanupAction::PruneBuildCacheId,
                });
            }
        }
    }

    targets.sort_by(|a, b| {
        format!("{}:{}", a.resource_type.as_str(), a.stable_id)
            .cmp(&format!("{}:{}", b.resource_type.as_str(), b.stable_id))
    });
    protected.sort_by(|a, b| {
        format!("{}:{}", a.resource_type.as_str(), a.stable_id)
            .cmp(&format!("{}:{}", b.resource_type.as_str(), b.stable_id))
    });

    let policy_summary = summarize_policy(policy, cache_hours);
    let conservative = targets.iter().any(|t| {
        matches!(
            t.resource_type,
            DockerResourceType::Images | DockerResourceType::Volumes
        )
    }) || inventory
        .build_cache
        .iter()
        .any(|c| c.shared && targets.iter().any(|t| t.stable_id == c.id));

    let estimated_reclaimable_bytes = targets
        .iter()
        .map(|t| t.estimated_reclaimable_bytes)
        .sum();

    let mut warnings = Vec::new();
    if conservative {
        warnings.push(DockerRiskWarning {
            code: "SHARED_STORAGE_ESTIMATE".to_string(),
            message: "镜像共享层或卷明细会使预计释放量偏保守，执行后以磁盘复查为准".to_string(),
        });
    }
    if policy.resource_types.contains(&DockerResourceType::Volumes) {
        warnings.push(DockerRiskWarning {
            code: "VOLUME_DELETE".to_string(),
            message: "卷删除不可恢复，并且会强制进入独立审批".to_string(),
        });
    }
    if targets.is_empty() {
        warnings.push(DockerRiskWarning {
            code: "NO_TARGETS".to_string(),
            message: "当前策略没有匹配到可安全删除的对象".to_string(),
        });
    }

    let target_digest = canonical_request_digest(&json!({
        "policy": policy,
        "targets": targets,
    }));

    Ok(CleanupSelection {
        policy: policy.clone(),
        policy_summary,
        targets,
        protected_resources: protected,
        target_digest,
        estimated_reclaimable_bytes,
        estimate_confidence: if conservative {
            "conservative".to_string()
        } else {
            "exact".to_string()
        },
        risk_warnings: warnings,
    })
}

pub fn make_cleanup_preview_result(
    plan_id: &str,
    server_id: &str,
    created_at: &str,
    expires_at: &str,
    sel: CleanupSelection,
) -> DockerCleanupPreviewResult {
    DockerCleanupPreviewResult {
        cleanup_plan_id: plan_id.to_string(),
        server_id: server_id.to_string(),
        generated_at: created_at.to_string(),
        expires_at: expires_at.to_string(),
        policy: sel.policy,
        policy_summary: sel.policy_summary,
        target_digest: sel.target_digest,
        targets: sel.targets,
        protected_resources: sel.protected_resources,
        estimated_reclaimable_bytes: sel.estimated_reclaimable_bytes,
        estimate_confidence: sel.estimate_confidence,
        risk_warnings: sel.risk_warnings,
    }
}

pub fn make_cleanup_execution_result(
    cleanup_plan_id: &str,
    before_inv: &DockerInventory,
    after_inv: &DockerInventory,
    deleted: Vec<DockerCleanupTarget>,
    failed: Vec<DockerCleanupFailedItem>,
    policy: &DockerCleanupPolicy,
) -> DockerCleanupExecutionResult {
    let before_running = running_container_ids(before_inv);
    let after_running = running_container_ids(after_inv);
    let running_unchanged = before_running.iter().all(|id| after_running.contains(id));
    let keep_latest_satisfied = retained_repo_mappings_unchanged(before_inv, after_inv, policy);

    let mut retained_tags: Vec<String> = policy
        .image_repository
        .as_deref()
        .map(|repo| {
            after_inv
                .images
                .iter()
                .flat_map(|img| {
                    img.repo_tags
                        .iter()
                        .filter(|tag| repository_of(tag) == repo)
                        .cloned()
                })
                .collect()
        })
        .unwrap_or_default();
    retained_tags.sort();

    let health_after = after_inv
        .containers
        .iter()
        .filter(|c| c.status == "running")
        .map(|c| DockerContainerHealthSummary {
            id: c.id.clone(),
            name: c.name.clone(),
            health: c.health.clone(),
        })
        .collect();

    let mut warnings = Vec::new();
    if !failed.is_empty() {
        warnings.push("部分目标删除失败，计划已消费；请重新预览后再处理".to_string());
    }
    if !running_unchanged {
        warnings.push("复查发现执行前运行的容器未保持运行，请立即人工检查".to_string());
    }
    if !keep_latest_satisfied {
        warnings.push("复查发现计划要求保留的镜像标签或其 image ID 已变化，请立即人工检查".to_string());
    }

    let freed = total_docker_bytes(&before_inv.disk_usage) as i64
        - total_docker_bytes(&after_inv.disk_usage) as i64;

    DockerCleanupExecutionResult {
        cleanup_plan_id: cleanup_plan_id.to_string(),
        before: before_inv.disk_usage.clone(),
        after: Some(after_inv.disk_usage.clone()),
        freed_bytes: Some(freed),
        deleted,
        failed,
        verification: DockerCleanupVerification {
            completed: true,
            error: None,
            running_containers_before: before_running,
            running_containers_after: after_running,
            running_containers_unchanged: running_unchanged,
            container_health_after: health_after,
            retained_repository_tags: retained_tags,
            keep_latest_satisfied,
        },
        warnings,
    }
}

pub fn make_incomplete_cleanup_execution_result(
    cleanup_plan_id: &str,
    before_inv: &DockerInventory,
    deleted: Vec<DockerCleanupTarget>,
    failed: Vec<DockerCleanupFailedItem>,
    error: String,
) -> DockerCleanupExecutionResult {
    DockerCleanupExecutionResult {
        cleanup_plan_id: cleanup_plan_id.to_string(),
        before: before_inv.disk_usage.clone(),
        after: None,
        freed_bytes: None,
        deleted,
        failed,
        verification: DockerCleanupVerification {
            completed: false,
            error: Some(error),
            running_containers_before: running_container_ids(before_inv),
            running_containers_after: Vec::new(),
            running_containers_unchanged: false,
            container_health_after: Vec::new(),
            retained_repository_tags: Vec::new(),
            keep_latest_satisfied: false,
        },
        warnings: vec!["删除已发生但自动复查未完成；计划已消费，请人工复查后重新预览".to_string()],
    }
}

fn select_images(
    images: &[InventoryImage],
    used_image_ids: &HashSet<String>,
    policy: &DockerCleanupPolicy,
    older_cutoff: DateTime<Utc>,
    targets: &mut Vec<DockerCleanupTarget>,
    protected: &mut Vec<DockerProtectedResource>,
) {
    let Some(repo) = policy.image_repository.as_deref().filter(|s| !s.is_empty()) else {
        for img in images.iter().filter(|i| i.repo_tags.is_empty()) {
            let norm = normalize_image_id(&img.id).to_string();
            if used_image_ids.contains(&norm) {
                protected.push(DockerProtectedResource {
                    resource_type: DockerResourceType::Images,
                    stable_id: img.id.clone(),
                    reason_code: "IMAGE_IN_USE".to_string(),
                    reason: "镜像被容器引用，禁止删除".to_string(),
                });
            } else if !is_at_or_before(&img.created_at, older_cutoff) {
                protected.push(DockerProtectedResource {
                    resource_type: DockerResourceType::Images,
                    stable_id: img.id.clone(),
                    reason_code: "RECENTLY_CREATED".to_string(),
                    reason: "镜像仍在保留时长内".to_string(),
                });
            } else {
                targets.push(DockerCleanupTarget {
                    resource_type: DockerResourceType::Images,
                    stable_id: img.id.clone(),
                    expected_image_id: Some(norm),
                    display_name: img.id.clone(),
                    size_bytes: img.size_bytes,
                    estimated_reclaimable_bytes: 0,
                    created_at: Some(img.created_at.clone()),
                    last_used_at: None,
                    action: DockerCleanupAction::RemoveImage,
                });
            }
        }
        return;
    };

    let mut versions: Vec<(&InventoryImage, Vec<String>)> = images
        .iter()
        .filter_map(|img| {
            let refs: Vec<String> = img
                .repo_tags
                .iter()
                .filter(|tag| repository_of(tag) == repo)
                .cloned()
                .collect();
            if refs.is_empty() {
                None
            } else {
                Some((img, refs))
            }
        })
        .collect();

    versions.sort_by(|(a, _), (b, _)| {
        parse_ts(&b.created_at)
            .cmp(&parse_ts(&a.created_at))
            .then_with(|| a.id.cmp(&b.id))
    });

    let keep_n = policy.keep_latest_tags.unwrap_or(1);
    let keep_ids: HashSet<String> = versions
        .iter()
        .take(keep_n)
        .map(|(img, _)| normalize_image_id(&img.id).to_string())
        .collect();

    for (img, refs) in versions {
        let norm = normalize_image_id(&img.id).to_string();
        if used_image_ids.contains(&norm) {
            for r in refs {
                protected.push(DockerProtectedResource {
                    resource_type: DockerResourceType::Images,
                    stable_id: r,
                    reason_code: "IMAGE_IN_USE".to_string(),
                    reason: "镜像被容器引用，禁止删除".to_string(),
                });
            }
        } else if keep_ids.contains(&norm) {
            for r in refs {
                protected.push(DockerProtectedResource {
                    resource_type: DockerResourceType::Images,
                    stable_id: r,
                    reason_code: "RETAINED_LATEST".to_string(),
                    reason: "镜像属于仓库最新保留版本".to_string(),
                });
            }
        } else if !is_at_or_before(&img.created_at, older_cutoff) {
            for r in refs {
                protected.push(DockerProtectedResource {
                    resource_type: DockerResourceType::Images,
                    stable_id: r,
                    reason_code: "RECENTLY_CREATED".to_string(),
                    reason: "镜像仍在保留时长内".to_string(),
                });
            }
        } else {
            for r in refs {
                targets.push(DockerCleanupTarget {
                    resource_type: DockerResourceType::Images,
                    stable_id: r.clone(),
                    expected_image_id: Some(norm.clone()),
                    display_name: r,
                    size_bytes: img.size_bytes,
                    estimated_reclaimable_bytes: 0,
                    created_at: Some(img.created_at.clone()),
                    last_used_at: None,
                    action: DockerCleanupAction::RemoveImage,
                });
            }
        }
    }
}

fn running_container_ids(inv: &DockerInventory) -> Vec<String> {
    let mut ids: Vec<String> = inv
        .containers
        .iter()
        .filter(|c| c.status == "running")
        .map(|c| c.id.clone())
        .collect();
    ids.sort();
    ids
}

fn retained_repo_mappings_unchanged(
    before: &DockerInventory,
    after: &DockerInventory,
    policy: &DockerCleanupPolicy,
) -> bool {
    let (Some(repo), Some(keep_n)) = (policy.image_repository.as_deref(), policy.keep_latest_tags) else {
        return true;
    };
    let mut before_imgs: Vec<&InventoryImage> = before
        .images
        .iter()
        .filter(|i| i.repo_tags.iter().any(|t| repository_of(t) == repo))
        .collect();
    before_imgs.sort_by(|a, b| {
        parse_ts(&b.created_at)
            .cmp(&parse_ts(&a.created_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    let expected_ids: HashSet<String> = before_imgs
        .into_iter()
        .take(keep_n)
        .map(|i| normalize_image_id(&i.id).to_string())
        .collect();

    let expected_mappings: Vec<String> = before
        .images
        .iter()
        .filter(|i| expected_ids.contains(normalize_image_id(&i.id)))
        .flat_map(|i| {
            let id = normalize_image_id(&i.id);
            i.repo_tags
                .iter()
                .filter(|t| repository_of(t) == repo)
                .map(move |t| format!("{t}={id}"))
        })
        .collect();

    let actual_mappings: HashSet<String> = after
        .images
        .iter()
        .flat_map(|i| {
            let id = normalize_image_id(&i.id);
            i.repo_tags
                .iter()
                .filter(|t| repository_of(t) == repo)
                .map(move |t| format!("{t}={id}"))
        })
        .collect();

    expected_mappings.iter().all(|m| actual_mappings.contains(m))
}

fn summarize_policy(policy: &DockerCleanupPolicy, cache_hours: u32) -> String {
    let resources = policy
        .resource_types
        .iter()
        .map(DockerResourceType::as_str)
        .collect::<Vec<_>>()
        .join("、");
    let mut parts = vec![
        format!("资源：{resources}"),
        format!("保留最近 {} 小时创建的对象", policy.older_than_hours),
    ];
    if policy.resource_types.contains(&DockerResourceType::BuildCache) {
        parts.push(format!("保留最近 {cache_hours} 小时使用的构建缓存"));
    }
    if let (Some(repo), Some(keep)) = (&policy.image_repository, policy.keep_latest_tags) {
        parts.push(format!("仓库 {repo} 保留最新 {keep} 个版本"));
    }
    if policy.resource_types.contains(&DockerResourceType::Volumes) {
        parts.push("仅未使用卷，独立审批".to_string());
    }
    parts.join("；")
}

fn total_docker_bytes(u: &DockerDiskUsageResult) -> u64 {
    u.images.size_bytes + u.containers.size_bytes + u.volumes.size_bytes + u.build_cache.size_bytes
}

fn marker(name: &str) -> String {
    format!("printf '%s\\n' '{SECTION_MARKER}{name}__'")
}

fn split_sections(stdout: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    let mut current = String::new();
    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.starts_with(SECTION_MARKER) && line.ends_with("__") && line.len() > SECTION_MARKER.len() + 2 {
            let name = &line[SECTION_MARKER.len()..line.len() - 2];
            current = name.to_string();
            map.entry(current.clone()).or_default();
        } else if !current.is_empty() && !line.is_empty() {
            map.entry(current.clone())
                .or_default()
                .push(raw_line.to_string());
        }
    }
    map
}

fn json_section(sections: &HashMap<String, Vec<String>>, name: &str) -> CoreResult<Vec<Value>> {
    let Some(lines) = sections.get(name) else {
        return Ok(Vec::new());
    };
    parse_json_lines(&lines.join("\n"))
}

fn parse_json_lines(raw: &str) -> CoreResult<Vec<Value>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let arr: Vec<Value> = serde_json::from_str(trimmed)?;
        return Ok(arr);
    }
    let mut out = Vec::new();
    for line in trimmed.lines() {
        let l = line.trim();
        if !l.is_empty() {
            out.push(serde_json::from_str(l)?);
        }
    }
    Ok(out)
}

pub fn parse_byte_size(input: &str) -> u64 {
    let Some(caps) = BYTE_SIZE_RE.captures(input.trim()) else {
        return 0;
    };
    let num: f64 = caps[1].parse().unwrap_or(0.0);
    let mul: f64 = match &caps[2] {
        "B" => 1.0,
        "kB" | "KB" => 1_000.0,
        "MB" => 1_000_000.0,
        "GB" => 1_000_000_000.0,
        "TB" => 1_000_000_000_000.0,
        "KiB" => 1024.0,
        "MiB" => 1024.0 * 1024.0,
        "GiB" => 1024.0 * 1024.0 * 1024.0,
        "TiB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    };
    (num * mul).round().max(0.0) as u64
}

fn parse_container_size(input: &str) -> (u64, Option<u64>) {
    let virt = VIRTUAL_SIZE_RE
        .captures(input)
        .and_then(|c| c.get(1))
        .map(|m| parse_byte_size(m.as_str()));
    (parse_byte_size(input), virt)
}

fn parse_io_pair(input: &str) -> (u64, u64) {
    let mut parts = input.split('/');
    let left = parts.next().unwrap_or("0B").trim();
    let right = parts.next().unwrap_or("0B").trim();
    (parse_byte_size(left), parse_byte_size(right))
}

fn parse_percent(input: &str) -> f64 {
    input
        .trim()
        .trim_end_matches('%')
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0)
        .unwrap_or(0.0)
}

fn as_object<'a>(val: &'a Value, ctx: &str) -> CoreResult<&'a serde_json::Map<String, Value>> {
    val.as_object()
        .ok_or_else(|| CoreError::Internal(format!("{ctx} JSON 格式无效")))
}

fn str_field(obj: &serde_json::Map<String, Value>, key: &str, fallback: &str) -> String {
    match obj.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => fallback.to_string(),
    }
}

fn u64_field(obj: &serde_json::Map<String, Value>, key: &str) -> u64 {
    match obj.get(key) {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}

fn int_field(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> u64 {
    for k in keys {
        if let Some(v) = obj.get(*k) {
            if let Some(n) = v.as_u64() {
                return n;
            }
            if let Some(s) = v.as_str().and_then(|s| s.parse::<u64>().ok()) {
                return s;
            }
        }
    }
    0
}

fn normalize_image_id(id: &str) -> &str {
    id.strip_prefix("sha256:").unwrap_or(id)
}

fn repository_of(reference: &str) -> &str {
    let slash = reference.rfind('/');
    if let Some(colon) = reference.rfind(':') {
        if slash.is_none_or(|s| colon > s) {
            return &reference[..colon];
        }
    }
    reference
}

fn is_safe_image_ref(val: &str) -> bool {
    val.len() <= 512 && SAFE_IMAGE_REF_RE.is_match(val)
}

fn assert_identifier<'a>(val: &'a str, re: &Regex, label: &str) -> CoreResult<&'a str> {
    if !re.is_match(val) {
        return Err(CoreError::InvalidInput(format!("{label} 格式无效: {val}")));
    }
    Ok(val)
}

fn parse_ts(s: &str) -> i64 {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.timestamp_millis())
        .or_else(|_| {
            // Docker inspect timestamps sometimes have space or nanoseconds
            chrono::DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S %z")
                .map(|d| d.timestamp_millis())
        })
        .unwrap_or(0)
}

fn is_at_or_before(ts_str: &str, cutoff: DateTime<Utc>) -> bool {
    let ts = parse_ts(ts_str);
    ts > 0 && ts <= cutoff.timestamp_millis()
}
