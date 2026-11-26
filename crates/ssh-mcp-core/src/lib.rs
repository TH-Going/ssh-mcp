pub mod db;
pub mod docker;
pub mod error;
pub mod events;
pub mod jobs;
pub mod mcp;
pub mod metrics;
pub mod models;
pub mod platform;
pub mod policy;
pub mod security;
pub mod skills_bundle;
pub mod ssh;
pub mod terminal;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use db::AppDatabase;
use error::CoreResult;
use events::CoreEventSink;
use jobs::JobService;
use mcp::McpServerController;
use metrics::MetricsScheduler;
use platform::acl::ensure_private_directory;
use security::{BackupService, SecretVault};
use ssh::SshService;
use terminal::TerminalService;

pub struct CoreRuntime {
    pub data_dir: PathBuf,
    pub stdio_command: String,
    pub db: Arc<AppDatabase>,
    pub backups: BackupService,
    pub ssh: Arc<SshService>,
    pub jobs: Arc<JobService>,
    pub terminals: Arc<TerminalService>,
    pub metrics: Arc<MetricsScheduler>,
    pub mcp: Arc<McpServerController>,
    pub events: Arc<dyn CoreEventSink>,
}

impl CoreRuntime {
    pub async fn initialize(
        data_dir: PathBuf,
        stdio_exe_path: &Path,
        events: Arc<dyn CoreEventSink>,
    ) -> CoreResult<Arc<Self>> {
        ensure_private_directory(&data_dir)?;
        let output_dir = data_dir.join("outputs");
        ensure_private_directory(&output_dir)?;

        let vault = SecretVault::load_or_create(&data_dir)?;
        let db_path = data_dir.join("ssh-mcp.db");
        let db = AppDatabase::open(&db_path, vault)?;

        let backups = BackupService::new(Arc::clone(&db));
        let ssh = SshService::new(Arc::clone(&db), Arc::clone(&events));
        let jobs = JobService::new(
            Arc::clone(&db),
            Arc::clone(&ssh),
            Arc::clone(&events),
            output_dir,
        )?;
        let terminals = TerminalService::new(
            Arc::clone(&db),
            Arc::clone(&ssh),
            Arc::clone(&events),
        );
        let metrics = MetricsScheduler::new(Arc::clone(&db), Arc::clone(&ssh));
        let mcp = McpServerController::new(Arc::clone(&db), Arc::clone(&jobs));

        let raw_settings = db.get_raw_settings()?;
        if raw_settings.mcp_enabled {
            if let Err(err) = mcp.start(raw_settings.mcp_port).await {
                tracing::warn!("Failed to start MCP HTTP listener on startup: {err}");
            }
        }

        let stdio_command = format!(
            "\"{}\" --endpoint http://127.0.0.1:{}/mcp",
            stdio_exe_path.display(),
            raw_settings.mcp_port
        );

        Ok(Arc::new(Self {
            data_dir,
            stdio_command,
            db,
            backups,
            ssh,
            jobs,
            terminals,
            metrics,
            mcp,
            events,
        }))
    }

    pub async fn shutdown(&self) {
        self.mcp.stop();
        self.metrics.shutdown();
        self.jobs.shutdown();
        self.terminals.shutdown_all().await;
    }
}
