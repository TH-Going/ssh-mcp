use std::sync::Arc;

use chrono::Utc;
use serde_json::{json, Value};
use ssh_mcp_core::db::AppDatabase;
use ssh_mcp_core::docker::{parse_inventory, select_cleanup_targets};
use ssh_mcp_core::events::NoopEventSink;
use ssh_mcp_core::jobs::{decode_utf8_page, JobService};
use ssh_mcp_core::mcp::{mcp_tools_catalog, McpServerController};
use ssh_mcp_core::models::{
    ApprovalDecision, ApprovalDecisionRequest, BackupApplyDecision, BackupImportAction,
    ConnectionStatus, ControlMode, DockerCleanupPolicy, DockerResourceType, HostKeyConfirmRequest,
    HostKeyStatus, ServerCreateRequest, ServerPatchRequest, SshAuthentication, ToolOperation,
};
use ssh_mcp_core::platform::dpapi::{dpapi_protect, dpapi_unprotect};
use ssh_mcp_core::policy::{
    evaluate_approval_policy, is_recognized_read_only_shell, ApprovalPolicyContext,
};
use ssh_mcp_core::security::{redact_text, BackupService, SecretVault};
use ssh_mcp_core::skills_bundle::install_skills_to_dir;
use ssh_mcp_core::ssh::{parse_metrics_output, SshService};

#[test]
fn windows_dpapi_and_vault_aad_tamper_protection() {
    let temp = tempfile::tempdir().expect("tempdir");
    let raw_secret = b"32-byte-secret-material-for-win11";
    let ct = dpapi_protect(raw_secret).expect("DPAPI protect should succeed on Windows");
    assert_ne!(ct.as_slice(), raw_secret);

    let pt = dpapi_unprotect(&ct).expect("DPAPI unprotect should succeed");
    assert_eq!(pt.as_slice(), raw_secret);

    // Vault persistence + reload via master-key.bin
    let vault1 = SecretVault::load_or_create(temp.path()).expect("create vault");
    let vault2 = SecretVault::load_or_create(temp.path()).expect("reload vault");

    let payload = ssh_mcp_core::models::SecretPayload {
        authentication: SshAuthentication::Password {
            password: "S3cret\"Pass\\123".to_string(),
        },
        sudo_password: Some("SudoRoot#99".to_string()),
    };
    let blob = vault1
        .encrypt_server_secret("server-alpha", &payload)
        .expect("encrypt");
    let decrypted = vault2
        .decrypt_server_secret("server-alpha", &blob)
        .expect("decrypt with same server_id");

    match &decrypted.authentication {
        SshAuthentication::Password { password } => assert_eq!(password, "S3cret\"Pass\\123"),
        _ => panic!("expected password auth"),
    }
    assert_eq!(decrypted.sudo_password.as_deref(), Some("SudoRoot#99"));

    // Cross-row AAD swap attack must be rejected by AES-256-GCM
    assert!(vault2
        .decrypt_server_secret("server-beta", &blob)
        .is_err());

    // Redaction covers both raw and JSON-escaped secret forms
    let log = r#"error with S3cret"Pass\123 and json \"S3cret\\\"Pass\\\\123\" and SudoRoot#99"#;
    let redacted = redact_text(
        log,
        &[
            "S3cret\"Pass\\123".to_string(),
            "SudoRoot#99".to_string(),
        ],
    );
    assert!(!redacted.contains("S3cret"));
    assert!(!redacted.contains("SudoRoot#99"));
    assert!(redacted.contains("[REDACTED]"));
}

#[test]
fn risk_policy_enforces_volume_delete_even_in_direct_mode() {
    let db = AppDatabase::in_memory_for_test().unwrap();
    let direct_srv = db
        .create_server(ServerCreateRequest {
            name: "prod-direct".to_string(),
            host: "10.0.1.10".to_string(),
            port: 22,
            username: "deploy".to_string(),
            environment: "生产".to_string(),
            control_mode: ControlMode::Direct,
            authentication: SshAuthentication::Password {
                password: "secretpassword".to_string(),
            },
            sudo_password: None,
        })
        .unwrap();

    // Arbitrary shell in Direct mode does NOT require approval
    let shell_op = ToolOperation::ShellExecute {
        command: "systemctl restart nginx".to_string(),
        sudo: false,
        timeout_seconds: None,
        reason: None,
    };
    let d1 = evaluate_approval_policy(&direct_srv, &shell_op, &ApprovalPolicyContext::default());
    assert!(!d1.requires_approval);
    assert_eq!(d1.matched_policy, "server.direct.shell.service_control");

    // Docker cleanup WITH volumes in Direct mode MUST STILL require approval
    let cleanup_op = ToolOperation::DockerCleanupExecute {
        cleanup_plan_id: "00000000-0000-0000-0000-000000000001".to_string(),
        timeout_seconds: None,
        reason: None,
    };
    let d2 = evaluate_approval_policy(
        &direct_srv,
        &cleanup_op,
        &ApprovalPolicyContext {
            cleanup_includes_volumes: true,
            policy_summary: Some("含卷删除".to_string()),
        },
    );
    assert!(d2.requires_approval);
    assert_eq!(d2.matched_policy, "docker.cleanup.volume_delete");

    // In Approval mode, dedicated read-only tools (even with sudo: true) and read-only shell commands
    // (including pipelines, &&, single-quoted awk $1, and sudo) do NOT require approval!
    let approval_srv = db
        .create_server(ServerCreateRequest {
            name: "prod-approval".to_string(),
            host: "10.0.1.11".to_string(),
            port: 22,
            username: "deploy".to_string(),
            environment: "生产".to_string(),
            control_mode: ControlMode::Approval,
            authentication: SshAuthentication::Password {
                password: "secretpassword".to_string(),
            },
            sudo_password: None,
        })
        .unwrap();

    let sudo_ro_tool = ToolOperation::DockerContainersList {
        state: ssh_mcp_core::models::DockerContainerStateFilter::Running,
        limit: 50,
        sudo: true,
        timeout_seconds: None,
    };
    let ro_tool_dec = evaluate_approval_policy(
        &approval_srv,
        &sudo_ro_tool,
        &ApprovalPolicyContext::default(),
    );
    assert!(!ro_tool_dec.requires_approval);
    assert_eq!(ro_tool_dec.matched_policy, "tool.read_only");

    let sudo_ro_shell = ToolOperation::ShellExecute {
        command: "ls -la /var/log | head -n 10 && sudo -n docker ps --format '{{.Names}}' && awk '{print $1}' /etc/hosts".to_string(),
        sudo: true,
        timeout_seconds: None,
        reason: None,
    };
    let ro_shell_dec = evaluate_approval_policy(
        &approval_srv,
        &sudo_ro_shell,
        &ApprovalPolicyContext::default(),
    );
    assert!(!ro_shell_dec.requires_approval);
    assert_eq!(ro_shell_dec.matched_policy, "shell.read_only.exempt");

    // FileDownload MUST still require approval in Approval mode
    let download_op = ToolOperation::FileDownload {
        remote_path: "/etc/nginx/nginx.conf".to_string(),
        local_path: "C:\\temp\\nginx.conf".to_string(),
        overwrite: false,
        timeout_seconds: None,
        reason: None,
    };
    let dl_dec = evaluate_approval_policy(
        &approval_srv,
        &download_op,
        &ApprovalPolicyContext::default(),
    );
    assert!(dl_dec.requires_approval);
    assert_eq!(dl_dec.matched_policy, "tool.file_write");

    // Read-only shell allowlist accepts common inspection commands & rejects injections/mutations
    assert!(is_recognized_read_only_shell("/usr/bin/uptime"));
    assert!(is_recognized_read_only_shell("df -h"));
    assert!(is_recognized_read_only_shell("ps aux | grep nginx | head -n 5"));
    assert!(is_recognized_read_only_shell("sudo systemctl status nginx && journalctl -u nginx -n 50 --no-pager"));
    assert!(is_recognized_read_only_shell("ip -br addr && ss -tulpn"));
    assert!(is_recognized_read_only_shell("find /var/log -name \"*.log\" -mtime +7"));
    assert!(is_recognized_read_only_shell("git -C /srv/app status && git -C /srv/app branch -a"));

    // Must reject metacharacter injection, command substitution, redirection, and mutating flags
    assert!(!is_recognized_read_only_shell("/bin/df -h; rm -rf /"));
    assert!(!is_recognized_read_only_shell("/bin/df $(whoami)"));
    assert!(!is_recognized_read_only_shell("echo \"$HOME\""));
    assert!(!is_recognized_read_only_shell("ls `id`"));
    assert!(!is_recognized_read_only_shell("echo hello > /tmp/out"));
    assert!(!is_recognized_read_only_shell("find /tmp -name '*.log' -delete"));
    assert!(!is_recognized_read_only_shell("find /tmp -exec sh -c 'id' \\;"));
    assert!(!is_recognized_read_only_shell("sed -i 's/foo/bar/g' /etc/hosts"));
    assert!(!is_recognized_read_only_shell("awk '{system(\"id\")}' /etc/hosts"));
    assert!(!is_recognized_read_only_shell("sudo -u root sh -c 'ls'"));
    assert!(!is_recognized_read_only_shell("sudo systemctl restart nginx"));
    assert!(!is_recognized_read_only_shell("docker rm my-container"));
    assert!(!is_recognized_read_only_shell("git branch -D feature"));
    assert!(!is_recognized_read_only_shell("journalctl --vacuum-time=2d"));
}

#[test]
fn server_tofu_host_keys_and_argon2id_portable_backup() {
    let temp = tempfile::tempdir().unwrap();
    let local_key_file = temp.path().join("id_ed25519_dummy");
    std::fs::write(&local_key_file, "-----BEGIN OPENSSH PRIVATE KEY-----\ndummy\n-----END OPENSSH PRIVATE KEY-----").unwrap();

    let db1 = AppDatabase::in_memory_for_test().unwrap();
    let srv = db1
        .create_server(ServerCreateRequest {
            name: "api-gw".to_string(),
            host: "10.0.2.8".to_string(),
            port: 22,
            username: "ops".to_string(),
            environment: "生产".to_string(),
            control_mode: ControlMode::Approval,
            authentication: SshAuthentication::LocalKeyPath {
                path: local_key_file.to_string_lossy().to_string(),
                passphrase: None,
            },
            sudo_password: Some("sudo-pass-1".to_string()),
        })
        .unwrap();

    // Observe initial host key -> HostKeyRequired
    let (obs1, is_changed) = db1
        .record_host_key_observation(&srv.id, "SHA256:AAAA1111")
        .unwrap();
    assert!(!is_changed);
    assert_eq!(obs1.connection_status, ConnectionStatus::HostKeyRequired);
    assert_eq!(
        obs1.pending_host_key_fingerprint.as_deref(),
        Some("SHA256:AAAA1111")
    );

    // Confirm host key -> Trusted
    let confirmed = db1
        .confirm_host_key(
            &srv.id,
            HostKeyConfirmRequest {
                fingerprint: "SHA256:AAAA1111".to_string(),
                expected_revision: obs1.revision,
            },
        )
        .unwrap();
    assert_eq!(confirmed.host_key_status, HostKeyStatus::Trusted);
    assert_eq!(
        confirmed.host_key_fingerprint.as_deref(),
        Some("SHA256:AAAA1111")
    );

    // Observe different key -> HostKeyChanged MITM warning!
    let (obs2, is_changed2) = db1
        .record_host_key_observation(&srv.id, "SHA256:BBBB2222")
        .unwrap();
    assert!(is_changed2);
    assert_eq!(obs2.connection_status, ConnectionStatus::HostKeyChanged);
    assert_eq!(obs2.host_key_status, HostKeyStatus::Changed);

    // Re-confirm back to AAAA1111 before exporting backup
    let _ = db1
        .confirm_host_key(
            &srv.id,
            HostKeyConfirmRequest {
                fingerprint: "SHA256:BBBB2222".to_string(),
                expected_revision: obs2.revision,
            },
        )
        .unwrap();

    // Optimistic revision check
    assert!(db1
        .patch_server(
            &srv.id,
            ServerPatchRequest {
                expected_revision: 999,
                name: Some("stale".to_string()),
                host: None,
                port: None,
                username: None,
                environment: None,
                control_mode: None,
            }
        )
        .is_err());

    // Export encrypted backup (converts local_key_path -> managed_key) & import into fresh DB
    let backup1 = BackupService::new(Arc::clone(&db1));
    let archive = backup1.export("StrongPassphrase!2026").unwrap();
    assert!(backup1.preflight(&archive, "WrongPassphrase!").is_err());

    let db2 = AppDatabase::in_memory_for_test().unwrap();
    let backup2 = BackupService::new(Arc::clone(&db2));
    let pre = backup2.preflight(&archive, "StrongPassphrase!2026").unwrap();
    assert_eq!(pre.servers.len(), 1);
    assert!(!pre.servers[0].conflict);

    let applied = backup2
        .apply(
            &pre.import_id,
            &[BackupApplyDecision {
                source_id: pre.servers[0].source_id.clone(),
                action: BackupImportAction::CreateNew,
            }],
        )
        .unwrap();
    assert_eq!(applied.created, 1);

    let restored = db2.list_servers().unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].name, "api-gw");
    assert_eq!(
        restored[0].auth_kind,
        ssh_mcp_core::models::AuthKind::ManagedKey
    );
    assert_eq!(
        restored[0].host_key_fingerprint.as_deref(),
        Some("SHA256:BBBB2222")
    );
}

#[test]
fn docker_cleanup_selection_and_utf8_pagination_and_metrics_parser() {
    let raw_inventory = r#"
__SSC_DOCKER_CONTAINERS__
{"ID":"111111111111","Name":"/nginx-live","ImageID":"sha256:aaaa11112222","Created":"2026-01-01T00:00:00Z","Status":"running","Health":"healthy","SizeRw":1024,"SizeRootFs":2048}
{"ID":"222222222222","Name":"/old-job","ImageID":"sha256:bbbb33334444","Created":"2026-01-01T00:00:00Z","Status":"exited","Health":"none","SizeRw":4096,"SizeRootFs":8192}
__SSC_DOCKER_IMAGES__
{"ID":"sha256:aaaa11112222","RepoTags":["app/web:v2"],"Created":"2026-01-01T00:00:00Z","Size":100000}
{"ID":"sha256:bbbb33334444","RepoTags":[],"Created":"2026-01-01T00:00:00Z","Size":200000}
{"ID":"sha256:cccc55556666","RepoTags":[],"Created":"2026-01-01T00:00:00Z","Size":300000}
__SSC_DOCKER_VOLUMES__
{"Name":"pgdata","Driver":"local","CreatedAt":"2026-01-01T00:00:00Z"}
__SSC_DOCKER_UNUSED_VOLUMES__
__SSC_DOCKER_BUILD_CACHE__
__SSC_DOCKER_DISK_USAGE__
{"Type":"Images","TotalCount":"3","Active":"1","Size":"600kB","Reclaimable":"300kB (50%)"}
"#;

    let inv = parse_inventory(raw_inventory).expect("parse docker inventory");
    assert_eq!(inv.containers.len(), 2);
    assert_eq!(inv.images.len(), 3);

    let policy = DockerCleanupPolicy {
        resource_types: vec![DockerResourceType::Containers, DockerResourceType::Images],
        older_than_hours: 24,
        build_cache_keep_used_within_hours: None,
        image_repository: None,
        keep_latest_tags: None,
        include_volumes: false,
    };
    let sel = select_cleanup_targets(&inv, &policy, Utc::now()).expect("select targets");
    // Container 111111111111 is running -> protected; 222222222222 is old exited -> target!
    // Image bbbb33334444 is referenced by exited container 222222222222 -> protected (`IMAGE_IN_USE`)!
    // Image cccc55556666 is dangling & unused -> target!
    assert_eq!(sel.targets.len(), 2);
    assert!(sel.targets.iter().any(|t| t.stable_id == "222222222222"));
    assert!(sel
        .targets
        .iter()
        .any(|t| t.stable_id == "sha256:cccc55556666"));
    assert!(sel
        .protected_resources
        .iter()
        .any(|p| p.stable_id == "111111111111" && p.reason_code == "RUNNING_CONTAINER"));

    // Multi-byte UTF-8 page boundary check (Chinese char '服' is 3 bytes)
    let text = "服务器控制台";
    let bytes = text.as_bytes();
    let (decoded_slice, consumed) = decode_utf8_page(&bytes[..5], false);
    assert_eq!(decoded_slice, "服");
    assert_eq!(consumed, 3);

    // Metrics output parser check
    let sample = "CPU1=1000 0 200 8800 0 0 0 0\nCPU2=1030 0 210 8860 0 0 0 0\nMEM=4096 8192\nDISK=600 1000\n";
    let m = parse_metrics_output(sample).expect("parse metrics");
    assert_eq!(m.cpu_percent, 40.0);
    assert_eq!(m.memory_percent, 50.0);
    assert_eq!(m.disk_percent, 60.0);
}

#[tokio::test]
async fn mcp_http_server_exposes_21_tools_enforces_origin_and_propagates_reason() {
    let temp = tempfile::tempdir().unwrap();
    let db = AppDatabase::in_memory_for_test().unwrap();
    let srv = db
        .create_server(ServerCreateRequest {
            name: "web-prod-01".to_string(),
            host: "10.0.1.12".to_string(),
            port: 22,
            username: "deploy".to_string(),
            environment: "生产".to_string(),
            control_mode: ControlMode::Approval,
            authentication: SshAuthentication::Password {
                password: "pass12345".to_string(),
            },
            sudo_password: None,
        })
        .unwrap();

    let events = Arc::new(NoopEventSink);
    let ssh = SshService::new(Arc::clone(&db), events.clone());
    let jobs = JobService::new(
        Arc::clone(&db),
        ssh,
        events,
        temp.path().join("outputs"),
    )
    .unwrap();
    let mcp = McpServerController::new(Arc::clone(&db), Arc::clone(&jobs));

    assert_eq!(mcp_tools_catalog().len(), 21);

    let addr = mcp.start(0).await.expect("bind ephemeral port");
    let url = format!("http://127.0.0.1:{}/mcp", addr.port());
    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    // 1. Browser cross-site Origin header MUST be blocked with 403 Forbidden
    let blocked = client
        .post(&url)
        .header("Origin", "https://malicious.example.com")
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }))
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), reqwest::StatusCode::FORBIDDEN);

    // 2. Initialize session with clientInfo.name = "claude-desktop"
    let init_resp = client
        .post(&url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "clientInfo": { "name": "claude-desktop", "version": "1.0.0" },
                "capabilities": {}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(init_resp.status(), reqwest::StatusCode::OK);
    let session_id = init_resp
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // 3. tools/list returns all 21 tools
    let list_val: Value = client
        .post(&url)
        .header("mcp-session-id", &session_id)
        .json(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tools = list_val["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 21);

    // 4. Call mutating tool `service_control` with operational `reason`
    let call_val: Value = client
        .post(&url)
        .header("mcp-session-id", &session_id)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "service_control",
                "arguments": {
                    "serverIds": [srv.id],
                    "service": "nginx",
                    "action": "restart",
                    "reason": "接入层 502 比例升高，重启 nginx 恢复"
                }
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let created_job = &call_val["result"]["structuredContent"];
    assert_eq!(created_job["status"], "waiting_approval");
    assert_eq!(created_job["requester"], "claude-desktop");
    assert_eq!(created_job["reason"], "接入层 502 比例升高，重启 nginx 恢复");
    let job_id = created_job["id"].as_str().unwrap().to_string();

    // 5. Verify pending approval carries requester, reason, and digest
    let pending = db.list_pending_approvals().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].requester, "claude-desktop");
    assert_eq!(
        pending[0].caller_reason.as_deref(),
        Some("接入层 502 比例升高，重启 nginx 恢复")
    );
    assert_eq!(pending[0].command_preview, "systemctl restart nginx");

    // 6. Verify `job_wait` immediately wakes with `waiting_approval`
    let wait_val: Value = client
        .post(&url)
        .header("mcp-session-id", &session_id)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "job_wait",
                "arguments": { "jobId": job_id, "waitMs": 5000 }
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        wait_val["result"]["structuredContent"]["wakeReason"],
        "waiting_approval"
    );

    // 7. Reject approval and verify job transitions to cancelled
    jobs.decide_approval(
        &pending[0].id,
        &ApprovalDecisionRequest {
            decision: ApprovalDecision::Reject,
            expected_request_digest: pending[0].request_digest.clone(),
            reason: Some("窗口期外暂缓重启".to_string()),
        },
    )
    .unwrap();
    let updated_job = db.get_job(&job_id).unwrap().unwrap();
    assert_eq!(updated_job.status, ssh_mcp_core::models::JobStatus::Cancelled);

    mcp.stop();
    jobs.shutdown();
}

#[test]
fn embedded_skills_bundle_installs_all_seven_skills_idempotently() {
    let temp = tempfile::tempdir().unwrap();
    let written1 = install_skills_to_dir(temp.path()).expect("first install");
    assert_eq!(written1, 15);
    assert!(temp.path().join("ssh-mcp-ops/SKILL.md").exists());
    assert!(temp
        .path()
        .join("ssh-mcp-ops/references/workflows.md")
        .exists());
    assert!(temp.path().join("ssh-mcp-docker-cleanup/SKILL.md").exists());
    assert!(temp.path().join(".ssh-mcp-skills-manifest.json").exists());

    // Second run should detect identical contents and write 0 files.
    let written2 = install_skills_to_dir(temp.path()).expect("second install");
    assert_eq!(written2, 0);

    // If a skill file on disk is outdated/modified, re-running automatically overwrites it!
    std::fs::write(temp.path().join("ssh-mcp-ops/SKILL.md"), "outdated skill").unwrap();
    let written3 = install_skills_to_dir(temp.path()).expect("auto update outdated skill");
    assert_eq!(written3, 1);

    // Anti-downgrade check: if manifest claims a higher future version (e.g. 99.0.0), an older binary must NOT overwrite it.
    std::fs::write(
        temp.path().join(".ssh-mcp-skills-manifest.json"),
        r#"{"appVersion":"99.0.0","bundleHash":"future","managedFiles":[]}"#,
    )
    .unwrap();
    std::fs::write(temp.path().join("ssh-mcp-ops/SKILL.md"), "future v99 skill").unwrap();
    let written4 = install_skills_to_dir(temp.path()).expect("skip downgrade");
    assert_eq!(written4, 0);
    assert_eq!(
        std::fs::read_to_string(temp.path().join("ssh-mcp-ops/SKILL.md")).unwrap(),
        "future v99 skill"
    );
}
