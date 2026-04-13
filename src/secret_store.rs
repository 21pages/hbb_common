#[cfg(not(target_os = "windows"))]
use crate::{config::APP_NAME, log};
#[cfg(not(target_os = "windows"))]
use once_cell::sync::OnceCell;

const MASTER_KEY_LEN: usize = sodiumoxide::crypto::secretbox::KEYBYTES;
#[cfg(not(target_os = "windows"))]
const ACCOUNT_NAME: &str = "master_key";
const USER_DATA_MAGIC_HEADER: [u8; 16] = [
    0xbe, 0xb6, 0x88, 0x39, 0x41, 0x15, 0x4b, 0xe7, 0x8d, 0x94, 0x10, 0x23, 0x59, 0x8f, 0x8b, 0x24,
];

#[cfg(not(target_os = "windows"))]
static MASTER_KEY: OnceCell<Vec<u8>> = OnceCell::new();

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
pub fn get_or_create_master_key() -> SecretStoreResult<Vec<u8>> {
    // `get_or_try_init` makes the load/generate/store/set sequence atomic for
    // concurrent first-use callers without caching transient initialization
    // errors.
    Ok(MASTER_KEY
        .get_or_try_init(|| {
            let service = APP_NAME.read().unwrap().clone();
            match load_secret(&service, ACCOUNT_NAME, MASTER_KEY_LEN) {
                Ok(key) => {
                    log::info!(
                        "Loaded existing master key from system secret store (service: {}, secret_len: {}, secret_hex: {})",
                        service,
                        key.len(),
                        crate::platform::bytes_to_hex(&key)
                    );
                    Ok(key)
                }
                Err(SecretStoreError::NotFound) => {
                    log::info!(
                        "Master key not found, generating new {} byte key (service: {})",
                        MASTER_KEY_LEN,
                        service
                    );
                    let key = sodiumoxide::randombytes::randombytes(MASTER_KEY_LEN);
                    if let Err(err) = store_secret(&service, ACCOUNT_NAME, &key) {
                        log::error!("Failed to persist generated master key: {err}");
                        return Err(err);
                    }
                    log::info!(
                        "Successfully created and stored new master key in system secret store (secret_len: {}, secret_hex: {})",
                        key.len(),
                        crate::platform::bytes_to_hex(&key)
                    );
                    Ok(key)
                }
                Err(err) => {
                    log::error!("Failed to load master key: {err}");
                    Err(err)
                }
            }
        })?
        .clone())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn secretbox_encrypt_user_data_raw(
    data: &[u8],
) -> Result<Vec<u8>, crate::password_security::CryptError> {
    use sodiumoxide::crypto::secretbox;
    use std::convert::TryInto;

    let keybuf = get_or_create_master_key()
        .map_err(|_| crate::password_security::CryptError::EncryptionFailed)?;
    let key = secretbox::Key(
        keybuf
            .try_into()
            .map_err(|_| crate::password_security::CryptError::InvalidData)?,
    );
    let nonce = secretbox::gen_nonce();
    let mut out = nonce.0.to_vec();
    out.extend(secretbox::seal(data, &nonce, &key));
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
    let keybuf = get_or_create_master_key()
        .map_err(|_| crate::password_security::CryptError::DecryptionFailed)?;
    let key = secretbox::Key(
        keybuf
            .try_into()
            .map_err(|_| crate::password_security::CryptError::InvalidData)?,
    );
    let nonce = secretbox::Nonce(
        data[..secretbox::NONCEBYTES]
            .try_into()
            .map_err(|_| crate::password_security::CryptError::InvalidData)?,
    );
    secretbox::open(&data[secretbox::NONCEBYTES..], &nonce, &key)
        .map_err(|_| crate::password_security::CryptError::DecryptionFailed)
}

#[cfg(not(target_os = "windows"))]
fn secretbox_user_data_min_len() -> usize {
    sodiumoxide::crypto::secretbox::NONCEBYTES + sodiumoxide::crypto::secretbox::MACBYTES
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
        Err(SecretStoreError::InvalidLength {
            expected: expected_len,
            actual: secret.len(),
        })
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
    fn test_once_cell_get_or_try_init_serializes_initialization() {
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
                    cache
                        .get_or_try_init(|| {
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
        assert_eq!(cache.get(), Some(&first));
    }

    #[test]
    fn test_once_cell_get_or_try_init_retries_after_error() {
        let cache = OnceCell::new();
        let init_calls = AtomicUsize::new(0);

        let first = cache.get_or_try_init(|| {
            init_calls.fetch_add(1, Ordering::SeqCst);
            Err(SecretStoreError::backend_message(
                "test init",
                "temporary failure",
            ))
        });
        assert!(first.is_err());
        assert!(cache.get().is_none());

        let second = cache
            .get_or_try_init(|| {
                init_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<Vec<u8>, SecretStoreError>(vec![7; MASTER_KEY_LEN])
            })
            .cloned()
            .unwrap();

        assert_eq!(init_calls.load(Ordering::SeqCst), 2);
        assert_eq!(second, vec![7; MASTER_KEY_LEN]);
        assert_eq!(cache.get(), Some(&second));
    }
}
