pub mod acl;
pub mod autostart;
pub mod dpapi;

use std::path::PathBuf;

/// Returns the default Windows 10/11 application data directory (`%LOCALAPPDATA%\sshMcp`).
pub fn default_data_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("SSH_MCP_DATA_DIR") {
        let trimmed = override_dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local_app_data).join("sshMcp");
    }
    std::env::temp_dir().join("sshMcp")
}
