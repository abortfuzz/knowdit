use color_eyre::eyre::eyre;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, KgError>;

#[derive(Debug, Error)]
pub enum KgError {
    #[error("database error: {0}")]
    Db(#[from] sea_orm::DbErr),

    #[error("LLM error: {0}")]
    Llm(#[from] llmy::LLMYError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(#[from] color_eyre::Report),
}

impl KgError {
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(eyre!("error: {}", msg.into()))
    }
}
