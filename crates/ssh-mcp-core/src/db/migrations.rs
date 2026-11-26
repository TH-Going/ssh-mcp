use rusqlite::Connection;

use crate::error::CoreResult;

pub fn run_migrations(conn: &Connection) -> CoreResult<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        PRAGMA busy_timeout = 5000;

        CREATE TABLE IF NOT EXISTS servers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL,
            environment TEXT NOT NULL DEFAULT '生产',
            control_mode TEXT NOT NULL CHECK (control_mode IN ('approval', 'direct')),
            auth_kind TEXT NOT NULL CHECK (auth_kind IN ('managed_key', 'password', 'local_key_path')),
            local_key_source TEXT,
            has_passphrase INTEGER NOT NULL DEFAULT 0,
            has_sudo_password INTEGER NOT NULL DEFAULT 0,
            connection_status TEXT NOT NULL DEFAULT 'unknown',
            last_checked_at TEXT,
            last_latency_ms INTEGER,
            last_error TEXT,
            cpu_percent REAL,
            memory_percent REAL,
            disk_percent REAL,
            metrics_sampled_at TEXT,
            revision INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS server_secrets (
            server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
            encrypted_payload BLOB NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS host_keys (
            server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
            trusted_fingerprint TEXT,
            pending_fingerprint TEXT,
            observed_at TEXT,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            mcp_enabled INTEGER NOT NULL DEFAULT 1,
            mcp_port INTEGER NOT NULL DEFAULT 8787,
            refresh_interval_seconds INTEGER NOT NULL DEFAULT 5,
            failure_alerts_enabled INTEGER NOT NULL DEFAULT 1,
            default_concurrency INTEGER NOT NULL DEFAULT 3,
            default_timeout_seconds INTEGER NOT NULL DEFAULT 300,
            allow_read_only_shell_without_approval INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            tool TEXT NOT NULL,
            requester TEXT NOT NULL DEFAULT '本机管理员',
            reason TEXT,
            operation_json TEXT NOT NULL,
            execution_json TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            revision INTEGER NOT NULL DEFAULT 1
        );

        CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at DESC);

        CREATE TABLE IF NOT EXISTS job_targets (
            id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            server_id TEXT NOT NULL,
            server_name TEXT NOT NULL,
            server_revision INTEGER NOT NULL,
            status TEXT NOT NULL,
            exit_code INTEGER,
            error TEXT,
            output_path TEXT,
            output_bytes INTEGER NOT NULL DEFAULT 0,
            output_expires_at TEXT,
            output_truncated INTEGER NOT NULL DEFAULT 0,
            executed_command TEXT,
            result_json TEXT,
            started_at TEXT,
            finished_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_job_targets_job_id ON job_targets(job_id);
        CREATE INDEX IF NOT EXISTS idx_job_targets_status ON job_targets(status);

        CREATE TABLE IF NOT EXISTS approvals (
            id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            target_id TEXT NOT NULL UNIQUE REFERENCES job_targets(id) ON DELETE CASCADE,
            server_id TEXT NOT NULL,
            server_name TEXT NOT NULL,
            requester TEXT NOT NULL DEFAULT '本机管理员',
            caller_reason TEXT,
            operation_json TEXT NOT NULL,
            content_digest TEXT,
            request_digest TEXT NOT NULL,
            risk TEXT NOT NULL CHECK (risk IN ('medium', 'high')),
            approval_reason TEXT NOT NULL,
            matched_policy TEXT NOT NULL,
            policy_summary TEXT,
            sudo INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'used')),
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            decided_at TEXT,
            decision_reason TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);

        CREATE TABLE IF NOT EXISTS docker_cleanup_plans (
            id TEXT PRIMARY KEY,
            server_id TEXT NOT NULL,
            server_revision INTEGER NOT NULL,
            preview_job_id TEXT NOT NULL,
            preview_target_id TEXT NOT NULL,
            execution_job_id TEXT,
            policy_json TEXT NOT NULL,
            policy_summary TEXT NOT NULL,
            sudo INTEGER NOT NULL DEFAULT 0,
            inventory_json TEXT NOT NULL,
            targets_json TEXT NOT NULL,
            target_digest TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('ready', 'claimed', 'completed', 'failed', 'expired', 'stale')),
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            entity_id TEXT,
            detail_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at);
        ",
    )?;

    conn.execute(
        "INSERT OR IGNORE INTO settings (
            id, mcp_enabled, mcp_port, refresh_interval_seconds, failure_alerts_enabled,
            default_concurrency, default_timeout_seconds, allow_read_only_shell_without_approval, updated_at
        ) VALUES (1, 1, 8787, 5, 1, 3, 300, 0, datetime('now'))",
        [],
    )?;

    Ok(())
}
