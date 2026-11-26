use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlMode {
    Approval,
    Direct,
}

impl ControlMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Direct => "direct",
        }
    }

    pub fn from_db(s: &str) -> Self {
        match s {
            "direct" => Self::Direct,
            _ => Self::Approval,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    ManagedKey,
    Password,
    LocalKeyPath,
}

impl AuthKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ManagedKey => "managed_key",
            Self::Password => "password",
            Self::LocalKeyPath => "local_key_path",
        }
    }

    pub fn from_db(s: &str) -> Self {
        match s {
            "password" => Self::Password,
            "local_key_path" => Self::LocalKeyPath,
            _ => Self::ManagedKey,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Unknown,
    Checking,
    Online,
    Offline,
    HostKeyRequired,
    HostKeyChanged,
}

impl ConnectionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Checking => "checking",
            Self::Online => "online",
            Self::Offline => "offline",
            Self::HostKeyRequired => "host_key_required",
            Self::HostKeyChanged => "host_key_changed",
        }
    }

    pub fn from_db(s: &str) -> Self {
        match s {
            "checking" => Self::Checking,
            "online" => Self::Online,
            "offline" => Self::Offline,
            "host_key_required" => Self::HostKeyRequired,
            "host_key_changed" => Self::HostKeyChanged,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyStatus {
    Unknown,
    Trusted,
    Changed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SshAuthentication {
    Password {
        password: String,
    },
    #[serde(rename_all = "camelCase")]
    ManagedKey {
        private_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    LocalKeyPath {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
    },
}

impl SshAuthentication {
    pub fn kind(&self) -> AuthKind {
        match self {
            Self::Password { .. } => AuthKind::Password,
            Self::ManagedKey { .. } => AuthKind::ManagedKey,
            Self::LocalKeyPath { .. } => AuthKind::LocalKeyPath,
        }
    }

    pub fn has_passphrase(&self) -> bool {
        match self {
            Self::Password { .. } => false,
            Self::ManagedKey { passphrase, .. } | Self::LocalKeyPath { passphrase, .. } => {
                passphrase.as_ref().is_some_and(|p| !p.is_empty())
            }
        }
    }

    pub fn zeroize_secrets(&mut self) {
        match self {
            Self::Password { password } => password.zeroize(),
            Self::ManagedKey {
                private_key,
                passphrase,
            } => {
                private_key.zeroize();
                if let Some(p) = passphrase {
                    p.zeroize();
                }
            }
            Self::LocalKeyPath { path, passphrase } => {
                path.zeroize();
                if let Some(p) = passphrase {
                    p.zeroize();
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretPayload {
    pub authentication: SshAuthentication,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sudo_password: Option<String>,
}

impl Drop for SecretPayload {
    fn drop(&mut self) {
        self.authentication.zeroize_secrets();
        if let Some(s) = &mut self.sudo_password {
            s.zeroize();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerMetrics {
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub disk_percent: f64,
    pub sampled_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub environment: String,
    pub control_mode: ControlMode,
    pub auth_kind: AuthKind,
    pub local_key_source: Option<String>,
    pub has_passphrase: bool,
    pub has_sudo_password: bool,
    pub connection_status: ConnectionStatus,
    pub host_key_status: HostKeyStatus,
    pub host_key_fingerprint: Option<String>,
    pub pending_host_key_fingerprint: Option<String>,
    pub last_checked_at: Option<String>,
    pub last_latency_ms: Option<u32>,
    pub last_error: Option<String>,
    pub metrics: Option<ServerMetrics>,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCreateRequest {
    pub name: String,
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub username: String,
    #[serde(default = "default_environment")]
    pub environment: String,
    pub control_mode: ControlMode,
    pub authentication: SshAuthentication,
    #[serde(default)]
    pub sudo_password: Option<String>,
}

fn default_ssh_port() -> u16 {
    22
}

fn default_environment() -> String {
    "生产".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerPatchRequest {
    pub expected_revision: i64,
    pub name: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub environment: Option<String>,
    pub control_mode: Option<ControlMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialReplaceRequest {
    pub expected_revision: i64,
    pub authentication: SshAuthentication,
    pub sudo_password: Option<Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyConfirmRequest {
    pub fingerprint: String,
    pub expected_revision: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectProbeResult {
    pub server: Server,
    pub latency_ms: Option<u32>,
}
