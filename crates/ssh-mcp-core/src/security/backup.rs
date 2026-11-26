use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db::AppDatabase;
use crate::error::{CoreError, CoreResult};
use crate::models::{
    BackupApplyDecision, BackupApplyResult, BackupImportAction, BackupPreflight,
    BackupPreflightItem, ServerCreateRequest, SettingsUpdateRequest, SshAuthentication,
};

const BACKUP_FORMAT: &str = "server-safe-control-backup";
const BACKUP_AAD: &[u8] = b"server-safe-control-backup:v1";
const KDF_MEMORY_KIB: u32 = 65536;
const KDF_PASSES: u32 = 3;
const KDF_PARALLELISM: u32 = 4;

#[derive(Debug, Serialize, Deserialize)]
struct BackupKdfMeta {
    algorithm: String,
    salt: String,
    memory: u32,
    passes: u32,
    parallelism: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct BackupCipherMeta {
    algorithm: String,
    nonce: String,
    tag: String,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BackupEnvelope {
    format: String,
    version: u32,
    kdf: BackupKdfMeta,
    cipher: BackupCipherMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PortableServerEntry {
    source_id: String,
    input: ServerCreateRequest,
    trusted_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PortableSettings {
    default_concurrency: usize,
    default_timeout_seconds: u32,
    #[serde(default)]
    allow_read_only_shell_without_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupPayload {
    version: u32,
    exported_at: String,
    servers: Vec<PortableServerEntry>,
    settings: PortableSettings,
}

struct PendingImport {
    payload: BackupPayload,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct BackupService {
    db: Arc<AppDatabase>,
    pending: Arc<Mutex<HashMap<String, PendingImport>>>,
}

impl BackupService {
    pub fn new(db: Arc<AppDatabase>) -> Self {
        Self {
            db,
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn export(&self, passphrase: &str) -> CoreResult<Vec<u8>> {
        if passphrase.chars().count() < 8 {
            return Err(CoreError::InvalidInput(
                "备份加密口令长度至少需要 8 个字符".to_string(),
            ));
        }

        let raw_records = self.db.export_backup_records()?;
        let mut servers = Vec::with_capacity(raw_records.len());
        for record in raw_records {
            let auth = match record.secret.authentication.clone() {
                SshAuthentication::LocalKeyPath { path, passphrase } => {
                    let trimmed = path.trim();
                    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("ssh-agent") {
                        SshAuthentication::LocalKeyPath {
                            path: "ssh-agent".to_string(),
                            passphrase,
                        }
                    } else {
                        let private_key = std::fs::read_to_string(trimmed).map_err(|e| {
                            CoreError::Io(std::io::Error::new(
                                e.kind(),
                                format!("导出备份时无法读取本机密钥文件 ({trimmed}): {e}"),
                            ))
                        })?;
                        SshAuthentication::ManagedKey {
                            private_key,
                            passphrase,
                        }
                    }
                }
                other => other,
            };

            servers.push(PortableServerEntry {
                source_id: record.server.id,
                input: ServerCreateRequest {
                    name: record.server.name,
                    host: record.server.host,
                    port: record.server.port,
                    username: record.server.username,
                    environment: record.server.environment,
                    control_mode: record.server.control_mode,
                    authentication: auth,
                    sudo_password: record.secret.sudo_password.clone(),
                },
                trusted_fingerprint: record.trusted_fingerprint,
            });
        }

        let settings_row = self.db.get_raw_settings()?;
        let payload = BackupPayload {
            version: 1,
            exported_at: Utc::now().to_rfc3339(),
            servers,
            settings: PortableSettings {
                default_concurrency: settings_row.default_concurrency,
                default_timeout_seconds: settings_row.default_timeout_seconds,
                allow_read_only_shell_without_approval: settings_row
                    .allow_read_only_shell_without_approval,
            },
        };

        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = derive_backup_key(passphrase, &salt)?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&*key)
            .map_err(|_| CoreError::Crypto("初始化备份加密器失败".to_string()))?;

        let plaintext = Zeroizing::new(serde_json::to_vec(&payload)?);
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &plaintext,
                    aad: BACKUP_AAD,
                },
            )
            .map_err(|_| CoreError::Crypto("加密备份内容失败".to_string()))?;

        let split_at = encrypted.len() - 16;
        let (ct, tag) = encrypted.split_at(split_at);

        let envelope = BackupEnvelope {
            format: BACKUP_FORMAT.to_string(),
            version: 1,
            kdf: BackupKdfMeta {
                algorithm: "argon2id".to_string(),
                salt: BASE64.encode(salt),
                memory: KDF_MEMORY_KIB,
                passes: KDF_PASSES,
                parallelism: KDF_PARALLELISM,
            },
            cipher: BackupCipherMeta {
                algorithm: "aes-256-gcm".to_string(),
                nonce: BASE64.encode(nonce_bytes),
                tag: BASE64.encode(tag),
                ciphertext: BASE64.encode(ct),
            },
        };

        Ok(serde_json::to_vec_pretty(&envelope)?)
    }

    pub fn preflight(&self, archive: &[u8], passphrase: &str) -> CoreResult<BackupPreflight> {
        if archive.len() > 100 * 1024 * 1024 {
            return Err(CoreError::InvalidInput("备份文件超过 100 MiB 上限".to_string()));
        }
        let envelope: BackupEnvelope = serde_json::from_slice(archive)
            .map_err(|_| CoreError::InvalidInput("备份文件格式无效".to_string()))?;

        if envelope.format != BACKUP_FORMAT
            || envelope.version != 1
            || envelope.kdf.algorithm != "argon2id"
            || envelope.kdf.memory != KDF_MEMORY_KIB
            || envelope.kdf.passes != KDF_PASSES
            || envelope.kdf.parallelism != KDF_PARALLELISM
            || envelope.cipher.algorithm != "aes-256-gcm"
        {
            return Err(CoreError::InvalidInput("不受支持的备份文件版本或参数".to_string()));
        }

        let salt = BASE64
            .decode(&envelope.kdf.salt)
            .map_err(|_| CoreError::InvalidInput("备份盐值损坏".to_string()))?;
        let nonce_bytes = BASE64
            .decode(&envelope.cipher.nonce)
            .map_err(|_| CoreError::InvalidInput("备份随机数损坏".to_string()))?;
        let tag = BASE64
            .decode(&envelope.cipher.tag)
            .map_err(|_| CoreError::InvalidInput("备份校验标签损坏".to_string()))?;
        let mut combined = BASE64
            .decode(&envelope.cipher.ciphertext)
            .map_err(|_| CoreError::InvalidInput("备份密文损坏".to_string()))?;

        if nonce_bytes.len() != 12 || tag.len() != 16 {
            return Err(CoreError::InvalidInput("备份加密参数长度无效".to_string()));
        }
        combined.extend_from_slice(&tag);

        let key = derive_backup_key(passphrase, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&*key)
            .map_err(|_| CoreError::Crypto("初始化备份解密器失败".to_string()))?;

        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: &combined,
                        aad: BACKUP_AAD,
                    },
                )
                .map_err(|_| CoreError::Crypto("备份口令错误或文件已被篡改".to_string()))?,
        );

        let payload: BackupPayload = serde_json::from_slice(&plaintext)
            .map_err(|_| CoreError::InvalidInput("备份内部数据损坏".to_string()))?;

        if payload.version != 1 || payload.servers.len() > 200 {
            return Err(CoreError::InvalidInput("备份服务器条目超出允许范围".to_string()));
        }

        let mut items = Vec::with_capacity(payload.servers.len());
        for s in &payload.servers {
            let existing = self
                .db
                .find_server_by_identity(&s.input.name, &s.input.host, s.input.port)?;
            items.push(BackupPreflightItem {
                source_id: s.source_id.clone(),
                name: s.input.name.clone(),
                host: s.input.host.clone(),
                port: s.input.port,
                conflict: existing.is_some(),
                existing_id: existing.map(|e| e.id),
            });
        }

        let import_id = Uuid::new_v4().to_string();
        let ttl = Duration::from_secs(600);
        let expires_at_dt = Utc::now() + chrono::Duration::seconds(600);
        {
            let mut map = self.pending.lock();
            map.retain(|_, v| v.expires_at > Instant::now());
            map.insert(
                import_id.clone(),
                PendingImport {
                    payload,
                    expires_at: Instant::now() + ttl,
                },
            );
        }

        Ok(BackupPreflight {
            import_id,
            version: 1,
            servers: items,
            expires_at: expires_at_dt.to_rfc3339(),
        })
    }

    pub fn apply(
        &self,
        import_id: &str,
        decisions: &[BackupApplyDecision],
    ) -> CoreResult<BackupApplyResult> {
        let pending = {
            let mut map = self.pending.lock();
            map.remove(import_id)
        };
        let Some(pending) = pending else {
            return Err(CoreError::Conflict(
                "备份导入预览已过期，请重新选择备份文件".to_string(),
            ));
        };
        if pending.expires_at <= Instant::now() {
            return Err(CoreError::Conflict(
                "备份导入预览已过期，请重新选择备份文件".to_string(),
            ));
        }

        let by_source: HashMap<&str, BackupImportAction> = decisions
            .iter()
            .map(|d| (d.source_id.as_str(), d.action))
            .collect();

        let mut result = BackupApplyResult {
            created: 0,
            overwritten: 0,
            skipped: 0,
        };

        for record in pending.payload.servers {
            let action = by_source
                .get(record.source_id.as_str())
                .copied()
                .unwrap_or(BackupImportAction::Skip);

            if action == BackupImportAction::Skip {
                result.skipped += 1;
                continue;
            }

            let existing = self.db.find_server_by_identity(
                &record.input.name,
                &record.input.host,
                record.input.port,
            )?;

            if action == BackupImportAction::Overwrite {
                if let Some(ex) = existing {
                    self.db.delete_server(&ex.id)?;
                    result.overwritten += 1;
                } else {
                    result.created += 1;
                }
            } else {
                result.created += 1;
            }

            let created = self.db.create_server(record.input)?;
            if let Some(fp) = record.trusted_fingerprint {
                self.db.set_trusted_host_key_direct(&created.id, Some(&fp))?;
            }
        }

        self.db.update_raw_settings(&SettingsUpdateRequest {
            default_concurrency: Some(pending.payload.settings.default_concurrency),
            default_timeout_seconds: Some(pending.payload.settings.default_timeout_seconds),
            allow_read_only_shell_without_approval: Some(
                pending
                    .payload
                    .settings
                    .allow_read_only_shell_without_approval,
            ),
            ..Default::default()
        })?;

        Ok(result)
    }
}

fn derive_backup_key(passphrase: &str, salt: &[u8]) -> CoreResult<Zeroizing<[u8; 32]>> {
    let params = Params::new(KDF_MEMORY_KIB, KDF_PASSES, KDF_PARALLELISM, Some(32))
        .map_err(|e| CoreError::Crypto(format!("Argon2id 参数无效: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|e| CoreError::Crypto(format!("Argon2id 密钥派生失败: {e}")))?;
    Ok(key)
}
