use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};
use crate::models::SecretPayload;
use crate::platform::dpapi::{dpapi_protect, dpapi_unprotect};

const VAULT_VERSION: u8 = 1;
const MASTER_KEY_FILE: &str = "master-key.bin";

#[derive(Clone)]
pub struct SecretVault {
    master_key: Zeroizing<[u8; 32]>,
}

impl SecretVault {
    /// Loads `%LOCALAPPDATA%\sshMcp\master-key.bin` via Windows DPAPI, or generates a new 32-byte key.
    pub fn load_or_create(data_dir: &Path) -> CoreResult<Self> {
        let key_path = data_dir.join(MASTER_KEY_FILE);
        if key_path.exists() {
            let protected = std::fs::read(&key_path)?;
            let plain = dpapi_unprotect(&protected)?;
            if plain.len() != 32 {
                return Err(CoreError::Crypto("主密钥长度损坏".to_string()));
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&plain);
            return Ok(Self { master_key: key });
        }

        let mut key = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *key);
        let protected = dpapi_protect(&*key)?;
        std::fs::write(&key_path, protected)?;
        Ok(Self { master_key: key })
    }

    /// Ephemeral random key constructor for isolated unit tests.
    pub fn with_ephemeral_key() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *key);
        Self { master_key: key }
    }

    pub fn encrypt_server_secret(&self, server_id: &str, secret: &SecretPayload) -> CoreResult<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&*self.master_key)
            .map_err(|_| CoreError::Crypto("初始化 AES-256-GCM 失败".to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = Zeroizing::new(serde_json::to_vec(secret)?);
        let aad = format!("server:{server_id}");
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| CoreError::Crypto("加密服务器凭据失败".to_string()))?;

        let mut out = Vec::with_capacity(1 + 12 + ciphertext.len());
        out.push(VAULT_VERSION);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt_server_secret(&self, server_id: &str, blob: &[u8]) -> CoreResult<SecretPayload> {
        if blob.len() < 1 + 12 + 16 || blob[0] != VAULT_VERSION {
            return Err(CoreError::Crypto("服务器加密凭据格式无效".to_string()));
        }
        let cipher = Aes256Gcm::new_from_slice(&*self.master_key)
            .map_err(|_| CoreError::Crypto("初始化 AES-256-GCM 失败".to_string()))?;

        let nonce = Nonce::from_slice(&blob[1..13]);
        let aad = format!("server:{server_id}");
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &blob[13..],
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| CoreError::Crypto("服务器凭据解密或防篡改校验失败".to_string()))?,
        );
        let payload: SecretPayload = serde_json::from_slice(&plaintext)?;
        Ok(payload)
    }
}
