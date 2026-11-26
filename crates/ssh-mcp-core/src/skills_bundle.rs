use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillsSyncReport {
    pub skill_count: usize,
    pub synced_targets: Vec<String>,
    pub files_written: usize,
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

/// Installs all embedded `ssh-mcp-*` skills into `target_skills_root` (idempotent write-if-changed).
pub fn install_skills_to_dir(target_skills_root: &Path) -> std::io::Result<usize> {
    std::fs::create_dir_all(target_skills_root)?;
    let mut written = 0usize;

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
    })
}

fn user_home_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}
