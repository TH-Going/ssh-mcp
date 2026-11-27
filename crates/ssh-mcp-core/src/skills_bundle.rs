use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

const MANIFEST_FILENAME: &str = ".ssh-mcp-skills-manifest.json";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

static SKILLS_SYNC_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillsSyncReport {
    pub skill_count: usize,
    pub synced_targets: Vec<String>,
    pub files_written: usize,
    pub app_version: String,
    pub bundle_hash: String,
    pub updated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstalledSkillsManifest {
    pub app_version: String,
    pub bundle_hash: String,
    #[serde(default)]
    pub managed_files: Vec<String>,
}

struct EmbeddedFile {
    rel_path: &'static str,
    content: &'static str,
}

const EMBEDDED_SKILL_NAMES: &[&str] = &[
    "ssh-mcp-ops",
    "ssh-mcp-start",
    "ssh-mcp-health",
    "ssh-mcp-service",
    "ssh-mcp-docker",
    "ssh-mcp-docker-cleanup",
    "ssh-mcp-job-followup",
];

const EMBEDDED_FILES: &[EmbeddedFile] = &[
    EmbeddedFile {
        rel_path: "ssh-mcp-ops/SKILL.md",
        content: include_str!("../../../skills/ssh-mcp-ops/SKILL.md"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-ops/references/workflows.md",
        content: include_str!("../../../skills/ssh-mcp-ops/references/workflows.md"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-ops/agents/openai.yaml",
        content: include_str!("../../../skills/ssh-mcp-ops/agents/openai.yaml"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-start/SKILL.md",
        content: include_str!("../../../skills/ssh-mcp-start/SKILL.md"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-start/agents/openai.yaml",
        content: include_str!("../../../skills/ssh-mcp-start/agents/openai.yaml"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-health/SKILL.md",
        content: include_str!("../../../skills/ssh-mcp-health/SKILL.md"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-health/agents/openai.yaml",
        content: include_str!("../../../skills/ssh-mcp-health/agents/openai.yaml"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-service/SKILL.md",
        content: include_str!("../../../skills/ssh-mcp-service/SKILL.md"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-service/agents/openai.yaml",
        content: include_str!("../../../skills/ssh-mcp-service/agents/openai.yaml"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-docker/SKILL.md",
        content: include_str!("../../../skills/ssh-mcp-docker/SKILL.md"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-docker/agents/openai.yaml",
        content: include_str!("../../../skills/ssh-mcp-docker/agents/openai.yaml"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-docker-cleanup/SKILL.md",
        content: include_str!("../../../skills/ssh-mcp-docker-cleanup/SKILL.md"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-docker-cleanup/agents/openai.yaml",
        content: include_str!("../../../skills/ssh-mcp-docker-cleanup/agents/openai.yaml"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-job-followup/SKILL.md",
        content: include_str!("../../../skills/ssh-mcp-job-followup/SKILL.md"),
    },
    EmbeddedFile {
        rel_path: "ssh-mcp-job-followup/agents/openai.yaml",
        content: include_str!("../../../skills/ssh-mcp-job-followup/agents/openai.yaml"),
    },
];

/// Deterministic content fingerprint of all embedded `ssh-mcp-*` skill files.
pub fn embedded_skills_bundle_hash() -> String {
    let mut h1: u64 = 0xcbf29ce484222325;
    let mut h2: u64 = 0x84222325cbf29ce4;
    for entry in EMBEDDED_FILES {
        for &b in entry.rel_path.as_bytes() {
            h1 ^= b as u64;
            h1 = h1.wrapping_mul(0x100000001b3);
        }
        h1 ^= 0xff;
        h1 = h1.wrapping_mul(0x100000001b3);

        for &b in entry.content.as_bytes() {
            h2 ^= b as u64;
            h2 = h2.wrapping_mul(0x100000001b3);
            h1 ^= b as u64;
            h1 = h1.wrapping_mul(0x100000001b3);
        }
    }
    format!("fnv128:{h1:016x}{h2:016x}")
}

#[allow(dead_code)]
pub fn embedded_app_version() -> &'static str {
    APP_VERSION
}

fn parse_semver_tuple(ver: &str) -> (u64, u64, u64) {
    let core = ver.trim().trim_start_matches('v').split('-').next().unwrap_or("");
    let mut parts = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

fn compare_semver(a: &str, b: &str) -> Ordering {
    parse_semver_tuple(a).cmp(&parse_semver_tuple(b))
}

/// Installs all embedded `ssh-mcp-*` skills into `target_skills_root` (idempotent write-if-changed,
/// cleans up removed legacy managed files, and prevents downgrade overwrites from older binaries).
pub fn install_skills_to_dir(target_skills_root: &Path) -> std::io::Result<usize> {
    let _guard = SKILLS_SYNC_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    std::fs::create_dir_all(target_skills_root)?;

    let manifest_path = target_skills_root.join(MANIFEST_FILENAME);
    let existing_manifest: Option<InstalledSkillsManifest> = std::fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok());

    // Prevent an outdated lingering `ssh-mcp-stdio.exe` binary from overwriting skills installed by a newer app!
    if let Some(existing) = &existing_manifest {
        if compare_semver(APP_VERSION, &existing.app_version) == Ordering::Less {
            return Ok(0);
        }
    }

    let current_hash = embedded_skills_bundle_hash();
    let current_managed: Vec<String> = EMBEDDED_FILES
        .iter()
        .map(|e| e.rel_path.to_string())
        .collect();

    let mut written = 0usize;

    // Clean up any stale files that were managed in a previous skill bundle but removed in the new version
    if let Some(existing) = &existing_manifest {
        for old_rel in &existing.managed_files {
            if old_rel.starts_with("ssh-mcp-")
                && !old_rel.contains("..")
                && !current_managed.iter().any(|cur| cur == old_rel)
            {
                let stale_path = target_skills_root.join(old_rel);
                if stale_path.exists() && std::fs::remove_file(&stale_path).is_ok() {
                    written += 1;
                }
            }
        }
    }

    for entry in EMBEDDED_FILES {
        let full_path = target_skills_root.join(entry.rel_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let unchanged = std::fs::read_to_string(&full_path)
            .map(|existing| existing == entry.content)
            .unwrap_or(false);
        if !unchanged {
            std::fs::write(&full_path, entry.content.as_bytes())?;
            written += 1;
        }
    }

    let manifest_needs_update = match &existing_manifest {
        Some(m) => {
            m.app_version != APP_VERSION
                || m.bundle_hash != current_hash
                || m.managed_files != current_managed
        }
        None => true,
    };

    if written > 0 || manifest_needs_update {
        let new_manifest = InstalledSkillsManifest {
            app_version: APP_VERSION.to_string(),
            bundle_hash: current_hash,
            managed_files: current_managed,
        };
        if let Ok(serialized) = serde_json::to_string_pretty(&new_manifest) {
            let _ = std::fs::write(&manifest_path, serialized.as_bytes());
        }
    }

    Ok(written)
}

/// Automatically detects installed AI agent skill directories under `%USERPROFILE%`
/// (plus any directory implied by `client_name` or `explicit_dir`) and syncs all 7 `ssh-mcp-*` skills.
pub fn auto_install_skills(
    client_name: Option<&str>,
    explicit_dir: Option<&Path>,
) -> std::io::Result<SkillsSyncReport> {
    let mut targets: Vec<PathBuf> = Vec::new();

    if let Some(dir) = explicit_dir {
        targets.push(dir.to_path_buf());
    }

    if let Some(home) = user_home_dir() {
        let client_lower = client_name.unwrap_or("").to_ascii_lowercase();
        let candidates: &[(&str, &str, &[&str])] = &[
            (".gemini", ".gemini\\config\\skills", &["antigravity", "gemini"]),
            (".codex", ".codex\\skills", &["codex"]),
            (".claude", ".claude\\skills", &["claude"]),
            (".agents", ".agents\\skills", &["agents", "amp", "opencode"]),
            (".cursor", ".cursor\\skills", &["cursor"]),
            (".windsurf", ".windsurf\\skills", &["windsurf", "codeium"]),
            (".cline", ".cline\\skills", &["cline"]),
            (".roo", ".roo\\skills", &["roo"]),
            (".workbuddy", ".workbuddy\\skills", &["workbuddy", "codebuddy"]),
        ];

        for (probe_root, skills_subpath, keywords) in candidates {
            let root_exists = home.join(probe_root).exists();
            let client_matches = keywords.iter().any(|kw| client_lower.contains(kw));
            if root_exists || client_matches {
                targets.push(home.join(skills_subpath));
            }
        }

        // Fallback if a fresh machine has none of the dot-folders yet: create `.agents\skills`.
        if targets.is_empty() {
            targets.push(home.join(".agents\\skills"));
        }
    }

    targets.sort();
    targets.dedup();

    let mut synced_targets = Vec::with_capacity(targets.len());
    let mut files_written = 0usize;

    for dir in targets {
        if let Ok(n) = install_skills_to_dir(&dir) {
            files_written += n;
            synced_targets.push(dir.to_string_lossy().to_string());
        }
    }

    Ok(SkillsSyncReport {
        skill_count: EMBEDDED_SKILL_NAMES.len(),
        synced_targets,
        files_written,
        app_version: APP_VERSION.to_string(),
        bundle_hash: embedded_skills_bundle_hash(),
        updated: files_written > 0,
    })
}

fn user_home_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}
