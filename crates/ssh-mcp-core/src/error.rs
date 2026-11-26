use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("{0}")]
    InvalidInput(String),

    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Conflict(String),

    #[error("REVISION_CONFLICT: 数据已被更新，请刷新后重试")]
    RevisionConflict,

    #[error("HOST_KEY_REQUIRED:{fingerprint}")]
    HostKeyRequired { fingerprint: String },

    #[error("HOST_KEY_CHANGED:{fingerprint}")]
    HostKeyChanged { fingerprint: String },

    #[error("操作超时")]
    Timeout,

    #[error("操作已取消")]
    Cancelled,

    #[error("数据库错误: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("序列化错误: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Crypto(String),

    #[error("{0}")]
    Ssh(String),

    #[error("{0}")]
    Internal(String),
}

pub type CoreResult<T> = Result<T, CoreError>;
