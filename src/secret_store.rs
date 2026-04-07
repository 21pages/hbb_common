use crate::{anyhow, config::APP_NAME, log};
use std::sync::OnceLock;

const MASTER_KEY_LEN: usize = sodiumoxide::crypto::secretbox::KEYBYTES;
const ACCOUNT_NAME: &str = "secret";

static MASTER_KEY: OnceLock<Vec<u8>> = OnceLock::new();

pub type SecretStoreResult<T> = Result<T, SecretStoreError>;

#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    #[error("secret not found")]
    NotFound,
    #[error("invalid secret length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("{context}: {source}")]
    Backend {
        context: &'static str,
        #[source]
        source: anyhow::Error,
    },
}

impl SecretStoreError {
    pub fn backend(context: &'static str, source: impl Into<anyhow::Error>) -> Self {
        Self::Backend {
            context,
            source: source.into(),
        }
    }

    pub fn backend_message(context: &'static str, message: impl Into<String>) -> Self {
        Self::Backend {
            context,
            source: anyhow::Error::msg(message.into()),
        }
    }
}

pub fn get_or_create_master_key() -> SecretStoreResult<Vec<u8>> {
    if let Some(key) = MASTER_KEY.get() {
        return Ok(key.clone());
    }

    let service = APP_NAME.read().unwrap().clone();
    let key = match load_secret(&service, ACCOUNT_NAME, MASTER_KEY_LEN) {
        Ok(key) => key,
        Err(SecretStoreError::NotFound) => {
            let key = sodiumoxide::randombytes::randombytes(MASTER_KEY_LEN);
            if let Err(err) = store_secret(&service, ACCOUNT_NAME, &key) {
                log::error!("Failed to persist generated master key: {err}");
                return Err(err);
            }
            key
        }
        Err(err) => {
            log::error!("Failed to load master key: {err}");
            return Err(err);
        }
    };

    let _ = MASTER_KEY.set(key.clone());
    Ok(key)
}

fn load_secret(service: &str, account: &str, expected_len: usize) -> SecretStoreResult<Vec<u8>> {
    with_expected_len(crate::platform::load_secret(service, account), expected_len)
}

fn store_secret(service: &str, account: &str, secret: &[u8]) -> SecretStoreResult<()> {
    crate::platform::store_secret(service, account, secret)
}

fn with_expected_len(
    secret: SecretStoreResult<Vec<u8>>,
    expected_len: usize,
) -> SecretStoreResult<Vec<u8>> {
    let secret = secret?;
    if secret.len() == expected_len {
        Ok(secret)
    } else {
        Err(SecretStoreError::InvalidLength {
            expected: expected_len,
            actual: secret.len(),
        })
    }
}
