#[cfg(not(target_os = "windows"))]
use crate::{config::APP_NAME, log};
#[cfg(not(target_os = "windows"))]
use once_cell::sync::OnceCell;

const MASTER_KEY_LEN: usize = sodiumoxide::crypto::secretbox::KEYBYTES;
#[cfg(not(target_os = "windows"))]
const SAFE_STORAGE_SUFFIX: &str = " Safe Storage";
const USER_DATA_MAGIC_HEADER: [u8; 16] = [
    0xbe, 0xb6, 0x88, 0x39, 0x41, 0x15, 0x4b, 0xe7, 0x8d, 0x94, 0x10, 0x23, 0x59, 0x8f, 0x8b, 0x24,
];

#[cfg(not(target_os = "windows"))]
static MASTER_KEY: OnceCell<Result<sodiumoxide::crypto::secretbox::Key, CachedSecretStoreError>> =
    OnceCell::new();

pub type SecretStoreResult<T> = Result<T, SecretStoreError>;

#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    #[error("secret not found")]
    NotFound,
    #[error("{context}: {message}")]
    Invalid {
        context: &'static str,
        message: String,
    },
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

    pub fn invalid(context: &'static str, message: impl Into<String>) -> Self {
        Self::Invalid {
            context,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone)]
enum CachedSecretStoreError {
    NotFound,
    Invalid {
        context: &'static str,
        message: String,
    },
    Backend {
        context: &'static str,
        message: String,
    },
}

impl From<SecretStoreError> for CachedSecretStoreError {
    fn from(err: SecretStoreError) -> Self {
        match err {
            SecretStoreError::NotFound => Self::NotFound,
            SecretStoreError::Invalid { context, message } => Self::Invalid { context, message },
            SecretStoreError::Backend { context, source } => Self::Backend {
                context,
                message: source.to_string(),
            },
        }
    }
}

impl CachedSecretStoreError {
    fn to_secret_store_error(&self) -> SecretStoreError {
        match self {
            Self::NotFound => SecretStoreError::NotFound,
            Self::Invalid { context, message } => {
                SecretStoreError::invalid(context, message.clone())
            }
            Self::Backend { context, message } => {
                SecretStoreError::backend_message(context, message.clone())
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn get_or_init_cached_secret<T, F>(
    cache: &OnceCell<Result<T, CachedSecretStoreError>>,
    init: F,
) -> SecretStoreResult<&T>
where
    F: FnOnce() -> SecretStoreResult<T>,
{
    match cache.get_or_init(|| init().map_err(CachedSecretStoreError::from)) {
        Ok(value) => Ok(value),
        Err(err) => Err(err.to_secret_store_error()),
    }
}

pub(crate) fn user_data_magic_header() -> &'static [u8] {
    &USER_DATA_MAGIC_HEADER
}

pub(crate) fn user_data_has_magic_header(payload: &[u8]) -> bool {
    payload.starts_with(user_data_magic_header())
}

pub(crate) fn user_data_add_magic_header(mut payload: Vec<u8>) -> Vec<u8> {
    let mut out = user_data_magic_header().to_vec();
    out.append(&mut payload);
    out
}

pub(crate) fn user_data_strip_magic_header(payload: &[u8]) -> (&[u8], bool) {
    if let Some(payload) = payload.strip_prefix(user_data_magic_header()) {
        (payload, true)
    } else {
        (payload, false)
    }
}

pub(crate) fn is_encrypted_user_data(payload: &[u8]) -> bool {
    user_data_has_magic_header(payload)
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn secretbox_encrypt_user_data_raw(
    data: &[u8],
) -> Result<Vec<u8>, crate::password_security::CryptError> {
    use sodiumoxide::crypto::secretbox;

    let key = master_secretbox_key()
        .map_err(|_| crate::password_security::CryptError::EncryptionFailed)?;
    let nonce = secretbox::gen_nonce();
    let mut out = nonce.0.to_vec();
    out.extend(secretbox::seal(data, &nonce, key));
    Ok(out)
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn secretbox_decrypt_user_data_raw(
    data: &[u8],
) -> Result<Vec<u8>, crate::password_security::CryptError> {
    use sodiumoxide::crypto::secretbox;
    use std::convert::TryInto;

    if data.len() < secretbox_user_data_min_len() {
        return Err(crate::password_security::CryptError::InvalidData);
    }
    let key = master_secretbox_key()
        .map_err(|_| crate::password_security::CryptError::DecryptionFailed)?;
    let nonce = secretbox::Nonce(
        data[..secretbox::NONCEBYTES]
            .try_into()
            .map_err(|_| crate::password_security::CryptError::InvalidData)?,
    );
    secretbox::open(&data[secretbox::NONCEBYTES..], &nonce, key)
        .map_err(|_| crate::password_security::CryptError::DecryptionFailed)
}

#[cfg(not(target_os = "windows"))]
fn secretbox_user_data_min_len() -> usize {
    sodiumoxide::crypto::secretbox::NONCEBYTES + sodiumoxide::crypto::secretbox::MACBYTES
}

#[cfg(not(target_os = "windows"))]
fn master_secretbox_key() -> SecretStoreResult<&'static sodiumoxide::crypto::secretbox::Key> {
    // Cache key load/failure to avoid repeatedly blocking on broken secret backend.
    get_or_init_cached_secret(&MASTER_KEY, load_or_create_master_secretbox_key)
}

#[cfg(not(target_os = "windows"))]
fn should_regenerate_master_secret(err: &SecretStoreError) -> bool {
    matches!(
        err,
        SecretStoreError::NotFound | SecretStoreError::Invalid { .. }
    )
}

#[cfg(not(target_os = "windows"))]
fn current_secret_store_names(app_name: &str) -> (String, String) {
    (
        format!("{app_name}{SAFE_STORAGE_SUFFIX}"),
        app_name.to_owned(),
    )
}

#[cfg(not(target_os = "windows"))]
fn load_or_create_master_secretbox_key() -> SecretStoreResult<sodiumoxide::crypto::secretbox::Key> {
    use std::convert::TryInto;

    let app_name = APP_NAME.read().unwrap().clone();
    let (service, account) = current_secret_store_names(&app_name);
    let create_and_store_key = || -> SecretStoreResult<Vec<u8>> {
        log::info!(
            "Generating new {} byte key for system secret store (service: {}, account: {})",
            MASTER_KEY_LEN,
            service,
            account
        );
        let key = sodiumoxide::randombytes::randombytes(MASTER_KEY_LEN);
        if let Err(err) = store_secret(&service, &account, &key) {
            log::error!("Failed to persist generated master key: {err}");
            return Err(err);
        }
        log::info!("Successfully created and stored new master key in system secret store");
        Ok(key)
    };
    let keybuf = match load_secret(&service, &account, MASTER_KEY_LEN) {
        Ok(key) => {
            log::info!(
                "Loaded existing master key from system secret store (service: {}, account: {})",
                service,
                account
            );
            log::info!(
                "==================== keybuf: {:?} ====================",
                key
            );
            key
        }
        Err(err) if should_regenerate_master_secret(&err) => {
            log::warn!(
                "Stored master key is missing or invalid, regenerating it (service: {}, account: {}, reason: {})",
                service,
                account,
                err
            );
            create_and_store_key()?
        }
        Err(err) => {
            log::error!("Failed to load master key: {err}");
            return Err(err);
        }
    };
    let actual = keybuf.len();
    Ok(sodiumoxide::crypto::secretbox::Key(
        keybuf.try_into().map_err(|_| {
            SecretStoreError::invalid(
                "stored secret has invalid length",
                format!("expected {MASTER_KEY_LEN} bytes, got {actual}"),
            )
        })?,
    ))
}

#[cfg(not(target_os = "windows"))]
fn load_secret(service: &str, account: &str, expected_len: usize) -> SecretStoreResult<Vec<u8>> {
    with_expected_len(crate::platform::load_secret(service, account), expected_len)
}

#[cfg(not(target_os = "windows"))]
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
        Err(SecretStoreError::invalid(
            "stored secret has invalid length",
            format!("expected {expected_len} bytes, got {}", secret.len()),
        ))
    }
}

#[cfg(all(test, not(target_os = "windows")))]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Barrier,
    };
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_cached_secret_init_serializes_initialization() {
        let cache = Arc::new(OnceCell::new());
        let init_calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(2));

        let handles: Vec<_> = (0..2)
            .map(|i| {
                let cache = Arc::clone(&cache);
                let init_calls = Arc::clone(&init_calls);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    get_or_init_cached_secret(&cache, || {
                        init_calls.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(50));
                        Ok::<Vec<u8>, SecretStoreError>(vec![i as u8 + 1; MASTER_KEY_LEN])
                    })
                    .cloned()
                    .unwrap()
                })
            })
            .collect();

        let mut results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        let second = results.pop().unwrap();
        let first = results.pop().unwrap();

        assert_eq!(init_calls.load(Ordering::SeqCst), 1);
        assert_eq!(first, second);
        assert!(matches!(cache.get(), Some(Ok(value)) if value == &first));
    }

    #[test]
    fn test_cached_secret_init_reuses_error() {
        let cache = OnceCell::new();
        let init_calls = AtomicUsize::new(0);

        let first = get_or_init_cached_secret(&cache, || {
            init_calls.fetch_add(1, Ordering::SeqCst);
            Err(SecretStoreError::backend_message(
                "test init",
                "temporary failure",
            ))
        });
        assert!(first.is_err());
        assert_eq!(init_calls.load(Ordering::SeqCst), 1);
        assert!(matches!(cache.get(), Some(Err(_))));

        let second = get_or_init_cached_secret(&cache, || {
            init_calls.fetch_add(1, Ordering::SeqCst);
            Ok::<Vec<u8>, SecretStoreError>(vec![7; MASTER_KEY_LEN])
        });

        assert!(second.is_err());
        assert_eq!(init_calls.load(Ordering::SeqCst), 1);
        assert!(format!("{}", second.unwrap_err()).contains("temporary failure"));
    }
}
