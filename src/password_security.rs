use crate::config::Config;
use sodiumoxide::base64;
use std::sync::{Arc, RwLock};

lazy_static::lazy_static! {
    pub static ref TEMPORARY_PASSWORD:Arc<RwLock<String>> = Arc::new(RwLock::new(get_auto_password()));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationMethod {
    OnlyUseTemporaryPassword,
    OnlyUsePermanentPassword,
    UseBothPasswords,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveMode {
    Both,
    Password,
    Click,
}

fn get_auto_password() -> String {
    let len = temporary_password_length();
    if Config::get_bool_option(crate::config::keys::OPTION_ALLOW_NUMERNIC_ONE_TIME_PASSWORD) {
        Config::get_auto_numeric_password(len)
    } else {
        Config::get_auto_password(len)
    }
}

// Should only be called in server
pub fn update_temporary_password() {
    *TEMPORARY_PASSWORD.write().unwrap() = get_auto_password();
}

// Should only be called in server
pub fn temporary_password() -> String {
    TEMPORARY_PASSWORD.read().unwrap().clone()
}

fn verification_method() -> VerificationMethod {
    let method = Config::get_option("verification-method");
    if method == "use-temporary-password" {
        VerificationMethod::OnlyUseTemporaryPassword
    } else if method == "use-permanent-password" {
        VerificationMethod::OnlyUsePermanentPassword
    } else {
        VerificationMethod::UseBothPasswords // default
    }
}

pub fn temporary_password_length() -> usize {
    let length = Config::get_option("temporary-password-length");
    if length == "8" {
        8
    } else if length == "10" {
        10
    } else {
        6 // default
    }
}

pub fn temporary_enabled() -> bool {
    verification_method() != VerificationMethod::OnlyUsePermanentPassword
}

pub fn permanent_enabled() -> bool {
    verification_method() != VerificationMethod::OnlyUseTemporaryPassword
}

pub fn has_valid_password() -> bool {
    temporary_enabled() && !temporary_password().is_empty()
        || permanent_enabled() && Config::has_permanent_password()
}

pub fn approve_mode() -> ApproveMode {
    let mode = Config::get_option("approve-mode");
    if mode == "password" {
        ApproveMode::Password
    } else if mode == "click" {
        ApproveMode::Click
    } else {
        ApproveMode::Both
    }
}

pub fn hide_cm() -> bool {
    approve_mode() == ApproveMode::Password
        && verification_method() == VerificationMethod::OnlyUsePermanentPassword
        && crate::config::option2bool("allow-hide-cm", &Config::get_option("allow-hide-cm"))
}

const VERSION_LEN: usize = 2;
pub const VERSION_00_UUID: &str = "00";
pub const VERSION_02_USER: &str = "02";

#[derive(Debug)]
pub enum CryptError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidData,
    Base64Error,
}

trait Cipher {
    fn version(&self) -> &'static str;
    fn encrypt(&self, data: &[u8], is_string: bool) -> Result<Vec<u8>, CryptError>;
    fn decrypt(&self, data: &[u8], is_string: bool) -> Result<Vec<u8>, CryptError>;
}

struct UuidCipher;
struct UserCipher;

static UUID_CIPHER: UuidCipher = UuidCipher;
static USER_CIPHER: UserCipher = UserCipher;

impl Cipher for UuidCipher {
    fn version(&self) -> &'static str {
        VERSION_00_UUID
    }

    fn encrypt(&self, data: &[u8], _is_string: bool) -> Result<Vec<u8>, CryptError> {
        symmetric_crypt_00_uuid(data, true)
            .map(|payload| base64::encode(payload, base64::Variant::Original).into_bytes())
            .map_err(|_| CryptError::EncryptionFailed)
    }

    fn decrypt(&self, data: &[u8], _is_string: bool) -> Result<Vec<u8>, CryptError> {
        let payload = base64::decode(data, base64::Variant::Original)
            .map_err(|_| CryptError::Base64Error)?;
        symmetric_crypt_00_uuid(&payload, false).map_err(|_| CryptError::DecryptionFailed)
    }
}

impl Cipher for UserCipher {
    fn version(&self) -> &'static str {
        VERSION_02_USER
    }

    fn encrypt(&self, data: &[u8], is_string: bool) -> Result<Vec<u8>, CryptError> {
        let payload = symmetric_crypt_02_user(data, true)?;
        if is_string {
            Ok(base64::encode(payload, base64::Variant::Original).into_bytes())
        } else {
            Ok(payload)
        }
    }

    fn decrypt(&self, data: &[u8], is_string: bool) -> Result<Vec<u8>, CryptError> {
        if is_string {
            let payload = base64::decode(data, base64::Variant::Original)
                .map_err(|_| CryptError::Base64Error)?;
            symmetric_crypt_02_user(&payload, false)
        } else {
            symmetric_crypt_02_user(data, false)
        }
    }
}

fn cipher_by_version(version: &str) -> Option<&'static dyn Cipher> {
    match version {
        VERSION_00_UUID => Some(&UUID_CIPHER),
        VERSION_02_USER => Some(&USER_CIPHER),
        _ => None,
    }
}

fn cipher_by_prefixed_data(v: &[u8]) -> Option<&'static dyn Cipher> {
    if v.len() <= VERSION_LEN {
        return None;
    }
    if v.starts_with(VERSION_00_UUID.as_bytes()) {
        Some(&UUID_CIPHER)
    } else if v.starts_with(VERSION_02_USER.as_bytes()) {
        Some(&USER_CIPHER)
    } else {
        None
    }
}

fn should_store_after_decrypt(
    version: &str,
    decrypted: &[u8],
    current_version: &str,
    is_string: bool,
) -> bool {
    if version == current_version {
        return false;
    }
    // Version 02 is user/platform scoped, so only request a store when the
    // current runtime can actually re-encrypt into that format. For older or
    // unknown target versions we keep returning true so callers can rewrite the
    // value on the next successful save.
    if current_version == VERSION_02_USER {
        if let Some(cipher) = cipher_by_version(current_version) {
            return cipher.encrypt(decrypted, is_string).is_ok();
        }
    }
    true
}

// Check if data is already encrypted by verifying:
// 1) known version prefix
// 2) a payload shape valid for that version
//    - strings always use version + base64(payload)
//    - version 02 vec uses version + raw_payload
//
// We intentionally avoid trying to decrypt here because key mismatch would cause
// false negatives.
fn is_encrypted(v: &[u8], is_string: bool) -> bool {
    let Some(cipher) = cipher_by_prefixed_data(v) else {
        return false;
    };

    let is_known_encrypted_payload = |version: &str, payload: &[u8]| match version {
        VERSION_00_UUID => payload.len() >= sodiumoxide::crypto::secretbox::MACBYTES,
        VERSION_02_USER => crate::secret_store::is_encrypted_user_data(payload),
        _ => false,
    };
    let is_base64_encrypted_payload =
        |version: &str, payload: &[u8]| match base64::decode(payload, base64::Variant::Original) {
            Ok(decoded) => is_known_encrypted_payload(version, &decoded),
            Err(_) => false,
        };

    let payload = &v[VERSION_LEN..];
    match cipher.version() {
        VERSION_00_UUID => is_base64_encrypted_payload(cipher.version(), payload),
        VERSION_02_USER => {
            if is_string {
                is_base64_encrypted_payload(cipher.version(), payload)
            } else {
                is_known_encrypted_payload(cipher.version(), payload)
            }
        }
        _ => false,
    }
}

pub fn encrypt_str_or_original(s: &str, version: &str, max_len: usize) -> String {
    if is_encrypted(s.as_bytes(), true) {
        log::error!("Duplicate encryption!");
        return s.to_owned();
    }
    if s.is_empty() {
        return s.to_owned();
    }
    if s.chars().count() > max_len {
        return String::default();
    }
    let mut versions = vec![version];
    if version == VERSION_02_USER {
        versions.push(VERSION_00_UUID);
    }
    for encrypt_version in versions {
        if let Some(cipher) = cipher_by_version(encrypt_version) {
            if let Ok(encrypted) = cipher.encrypt(s.as_bytes(), true) {
                if let Ok(encrypted) = String::from_utf8(encrypted) {
                    return encrypt_version.to_owned() + &encrypted;
                }
            }
        }
    }
    s.to_owned()
}

// String: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
// note: s.len() return length in bytes, s.chars().count() return char count
//       avoid slicing `&str` by raw byte offsets unless the boundary is known-valid UTF-8
pub fn decrypt_str_or_original(s: &str, current_version: &str) -> (String, bool, bool) {
    if let Some(cipher) = cipher_by_prefixed_data(s.as_bytes()) {
        let payload = s[VERSION_LEN..].as_bytes();
        if let Ok(v) = cipher.decrypt(payload, true) {
            let store = should_store_after_decrypt(cipher.version(), &v, current_version, true);
            return (String::from_utf8_lossy(&v).to_string(), true, store);
        }
    }

    // For values that already look encrypted (version prefix + base64), avoid
    // repeated store on each load when decryption fails.
    (
        s.to_owned(),
        false,
        !s.is_empty() && !is_encrypted(s.as_bytes(), true),
    )
}

pub fn encrypt_vec_or_original(v: &[u8], version: &str, max_len: usize) -> Vec<u8> {
    if is_encrypted(v, false) {
        log::error!("Duplicate encryption!");
        return v.to_owned();
    }
    if v.is_empty() {
        return v.to_owned();
    }
    if v.len() > max_len {
        return vec![];
    }
    let mut versions = vec![version];
    if version == VERSION_02_USER {
        versions.push(VERSION_00_UUID);
    }
    for encrypt_version in versions {
        if let Some(cipher) = cipher_by_version(encrypt_version) {
            if let Ok(mut encrypted) = cipher.encrypt(v, false) {
                let mut prefixed = encrypt_version.as_bytes().to_vec();
                prefixed.append(&mut encrypted);
                return prefixed;
            }
        }
    }
    v.to_owned()
}

// Vec<u8>: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
pub fn decrypt_vec_or_original(v: &[u8], current_version: &str) -> (Vec<u8>, bool, bool) {
    if let Some(cipher) = cipher_by_prefixed_data(v) {
        let payload = &v[VERSION_LEN..];
        if let Ok(v) = cipher.decrypt(payload, false) {
            let store = should_store_after_decrypt(cipher.version(), &v, current_version, false);
            return (v, true, store);
        }
    }

    // For values that already look encrypted (version prefix + raw payload
    // shape), avoid repeated store on each load when decryption fails.
    (
        v.to_owned(),
        false,
        !v.is_empty() && !is_encrypted(v, false),
    )
}

pub fn encrypt_user_sync_file(data: &[u8], max_len: usize) -> Option<Vec<u8>> {
    #[cfg(target_os = "android")]
    {
        let encrypted = encrypt_vec_or_original(data, VERSION_00_UUID, max_len);
        let (decrypted, success, _) = decrypt_vec_or_original(&encrypted, VERSION_00_UUID);
        (success && decrypted == data).then_some(encrypted)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = max_len;
        symmetric_crypt_02_user(data, true).ok()
    }
}

pub fn decrypt_user_sync_file(data: &[u8]) -> Option<Vec<u8>> {
    #[cfg(target_os = "android")]
    {
        let (decrypted, success, _) = decrypt_vec_or_original(data, VERSION_00_UUID);
        success.then_some(decrypted)
    }
    #[cfg(not(target_os = "android"))]
    {
        symmetric_crypt_02_user(data, false).ok()
    }
}

fn symmetric_crypt_00_uuid(data: &[u8], encrypt: bool) -> Result<Vec<u8>, CryptError> {
    use sodiumoxide::crypto::secretbox;
    use std::convert::TryInto;

    let uuid = crate::get_uuid();
    let mut keybuf = uuid.clone();
    keybuf.resize(secretbox::KEYBYTES, 0);
    let key = secretbox::Key(keybuf.try_into().map_err(|_| CryptError::InvalidData)?);
    let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

    if encrypt {
        Ok(secretbox::seal(data, &nonce, &key))
    } else {
        let res = secretbox::open(data, &nonce, &key);
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if res.is_err() {
            // Fallback: try pk if uuid decryption failed (in case encryption used pk due to machine_uid failure)
            if let Some(key_pair) = Config::get_existing_key_pair() {
                let pk = key_pair.1;
                if pk != uuid {
                    let mut keybuf = pk;
                    keybuf.resize(secretbox::KEYBYTES, 0);
                    let pk_key = secretbox::Key(keybuf.try_into().map_err(|_| CryptError::InvalidData)?);
                    return secretbox::open(data, &nonce, &pk_key)
                        .map_err(|_| CryptError::DecryptionFailed);
                }
            }
        }
        res.map_err(|_| CryptError::DecryptionFailed)
    }
}

// Version 02 uses platform/user-scoped encryption and only decrypts payloads
// produced by the current platform/user-scoped path.
pub fn symmetric_crypt_02_user(data: &[u8], encrypt: bool) -> Result<Vec<u8>, CryptError> {
    if encrypt {
        #[cfg(target_os = "windows")]
        let payload = crate::platform::dpapi_encrypt_bytes(data)
            .map_err(|_| CryptError::EncryptionFailed)?;
        #[cfg(not(target_os = "windows"))]
        let payload = crate::secret_store::secretbox_encrypt_user_data_raw(data)?;

        Ok(crate::secret_store::user_data_add_magic_header(payload))
    } else {
        let (payload, has_header) = crate::secret_store::user_data_strip_magic_header(data);
        if !has_header {
            return Err(CryptError::InvalidData);
        }

        #[cfg(target_os = "windows")]
        {
            crate::platform::dpapi_decrypt_bytes(payload)
                .map_err(|_| CryptError::DecryptionFailed)
        }
        #[cfg(not(target_os = "windows"))]
        {
            crate::secret_store::secretbox_decrypt_user_data_raw(payload)
        }
    }
}

mod test {

    #[test]
    fn test() {
        use super::*;
        use rand::{thread_rng, Rng};
        use std::time::Instant;

        let version_uuid = VERSION_00_UUID;
        let version_user = VERSION_02_USER;
        let max_len = 128;

        println!("test str");
        let data = "1ü1111";
        let encrypted = encrypt_str_or_original(data, version_user, max_len);
        let (decrypted, succ, store) = decrypt_str_or_original(&encrypted, version_user);
        println!("data: {data}");
        println!("encrypted: {encrypted}");
        println!("decrypted: {decrypted}");
        assert_eq!(data, decrypted);
        assert_eq!(version_user, &encrypted[..2]);
        assert!(succ);
        assert!(!store);
        let (_, _, store) = decrypt_str_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_str_or_original(&decrypted, version_user).1);
        assert_eq!(
            encrypt_str_or_original(&encrypted, version_user, max_len),
            encrypted
        );

        println!("test vec");
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        let encrypted = encrypt_vec_or_original(&data, version_user, max_len);
        let (decrypted, succ, store) = decrypt_vec_or_original(&encrypted, version_user);
        println!("data: {data:?}");
        println!("encrypted: {encrypted:?}");
        println!("decrypted: {decrypted:?}");
        assert_eq!(data, decrypted);
        assert_eq!(version_user.as_bytes(), &encrypted[..2]);
        assert!(!store);
        assert!(succ);
        let (_, _, store) = decrypt_vec_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_vec_or_original(&decrypted, version_user).1);
        assert_eq!(
            encrypt_vec_or_original(&encrypted, version_user, max_len),
            encrypted
        );

        println!("test original");
        let data = version_user.to_string() + "Hello World";
        let (decrypted, succ, store) = decrypt_str_or_original(&data, version_user);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let verbytes = version_user.as_bytes();
        let data: Vec<u8> = vec![verbytes[0], verbytes[1], 1, 2, 3, 4, 5, 6];
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version_user);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let (_, succ, store) = decrypt_str_or_original("", version_user);
        assert!(!store);
        assert!(!succ);
        let (_, succ, store) = decrypt_vec_or_original(&[], version_user);
        assert!(!store);
        assert!(!succ);
        let data = "1ü1111";
        assert_eq!(decrypt_str_or_original(data, version_user).0, data);
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        assert_eq!(decrypt_vec_or_original(&data, version_user).0, data);

        println!("test version 00 compatibility");
        let legacy_encrypted = encrypt_str_or_original("legacy", version_uuid, max_len);
        let (legacy_decrypted, succ, store) =
            decrypt_str_or_original(&legacy_encrypted, version_user);
        assert_eq!(legacy_decrypted, "legacy");
        assert!(succ);
        assert!(store);

        // Base64-shaped "00" prefixed values shorter than MACBYTES are treated
        // as original/plain values and should be stored.
        let data = "00YWJjZA==";
        let (decrypted, succ, store) = decrypt_str_or_original(data, version_user);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);
        let data = b"00YWJjZA==".to_vec();
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version_user);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);

        // When decoded length reaches MACBYTES, it is treated as encrypted-like
        // and should not trigger repeated store.
        let exact_mac = vec![0u8; sodiumoxide::crypto::secretbox::MACBYTES];
        let exact_mac_b64 =
            sodiumoxide::base64::encode(&exact_mac, sodiumoxide::base64::Variant::Original);
        let data = format!("00{exact_mac_b64}");
        let (_, succ, store) = decrypt_str_or_original(&data, version_user);
        assert!(!succ);
        assert!(!store);
        let data = data.into_bytes();
        let (_, succ, store) = decrypt_vec_or_original(&data, version_user);
        assert!(!succ);
        assert!(!store);

        println!("test speed");
        let test_speed = |len: usize, name: &str| {
            let mut data: Vec<u8> = vec![];
            let mut rng = thread_rng();
            for _ in 0..len {
                data.push(rng.gen_range(0..255));
            }
            let start: Instant = Instant::now();
            let encrypted = encrypt_vec_or_original(&data, version_user, len);
            assert_ne!(data, decrypted);
            let t1 = start.elapsed();
            let start = Instant::now();
            let (decrypted, _, _) = decrypt_vec_or_original(&encrypted, version_user);
            let t2 = start.elapsed();
            assert_eq!(data, decrypted);
            println!("{name}");
            println!("encrypt:{:?}, decrypt:{:?}", t1, t2);

            let start: Instant = Instant::now();
            let encrypted = base64::encode(&data, base64::Variant::Original);
            let t1 = start.elapsed();
            let start = Instant::now();
            let decrypted = base64::decode(&encrypted, base64::Variant::Original).unwrap();
            let t2 = start.elapsed();
            assert_eq!(data, decrypted);
            println!("base64, encrypt:{:?}, decrypt:{:?}", t1, t2,);
        };
        test_speed(128, "128");
        test_speed(1024, "1k");
        test_speed(1024 * 1024, "1M");
        test_speed(10 * 1024 * 1024, "10M");
        test_speed(100 * 1024 * 1024, "100M");
    }

    #[test]
    fn test_is_encrypted() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use sodiumoxide::crypto::secretbox;

        // Empty data should not be considered encrypted
        assert!(!is_encrypted(b"", true));
        assert!(!is_encrypted(b"0", true));
        assert!(!is_encrypted(b"00", true));
        assert!(!is_encrypted(b"", false));
        assert!(!is_encrypted(b"0", false));
        assert!(!is_encrypted(b"00", false));

        // Data without "00" prefix should not be considered encrypted
        assert!(!is_encrypted(b"01abcd", true));
        assert!(!is_encrypted(b"99abcd", true));
        assert!(!is_encrypted(b"hello world", true));
        assert!(!is_encrypted(b"01abcd", false));
        assert!(!is_encrypted(b"99abcd", false));
        assert!(!is_encrypted(b"hello world", false));

        // Data with "00" prefix but invalid base64 should not be considered encrypted
        assert!(!is_encrypted(b"00!!!invalid base64!!!", true));
        assert!(!is_encrypted(b"00@#$%", true));
        assert!(!is_encrypted(b"00!!!invalid base64!!!", false));
        assert!(!is_encrypted(b"00@#$%", false));

        // Data with "00" prefix and valid base64 but shorter than MACBYTES is not encrypted
        assert!(!is_encrypted(b"00YWJjZA==", true)); // "abcd" in base64
        assert!(!is_encrypted(b"00SGVsbG8gV29ybGQ=", true)); // "Hello World" in base64
        assert!(!is_encrypted(b"00YWJjZA==", false));
        assert!(!is_encrypted(b"00SGVsbG8gV29ybGQ=", false));

        // Data with "00" prefix and valid base64 with decoded len == MACBYTES is considered encrypted
        let exact_mac = vec![0u8; secretbox::MACBYTES];
        let exact_mac_b64 = encode(&exact_mac, Variant::Original);
        let exact_mac_candidate = format!("00{exact_mac_b64}");
        assert!(is_encrypted(exact_mac_candidate.as_bytes(), true));
        assert!(is_encrypted(exact_mac_candidate.as_bytes(), false));

        // Real encrypted data should be detected
        let version_uuid = VERSION_00_UUID;
        let max_len = 128;
        let encrypted_str = encrypt_str_or_original("1", version_uuid, max_len);
        assert!(is_encrypted(encrypted_str.as_bytes(), true));
        let encrypted_vec = encrypt_vec_or_original(b"1", version_uuid, max_len);
        assert!(is_encrypted(&encrypted_vec, false));

        // Original unencrypted data should not be detected as encrypted
        assert!(!is_encrypted(b"1", true));
        assert!(!is_encrypted("1".as_bytes(), false));
    }

    #[test]
    fn test_encrypted_payload_min_len_macbytes() {
        use super::*;
        use sodiumoxide::base64::{decode, Variant};
        use sodiumoxide::crypto::secretbox;

        let version_user_scope = VERSION_02_USER;
        let max_len = 128;

        let encrypted_str = encrypt_str_or_original("1", version_user_scope, max_len);
        let decoded = decode(&encrypted_str.as_bytes()[VERSION_LEN..], Variant::Original).unwrap();
        assert!(
            decoded.len() >= secretbox::MACBYTES,
            "decoded encrypted payload must be at least MACBYTES"
        );

        let encrypted_vec = encrypt_vec_or_original(b"1", version_user_scope, max_len);
        assert!(
            encrypted_vec[VERSION_LEN..].len() >= secretbox::MACBYTES,
            "encrypted vec payload must be at least MACBYTES"
        );
    }

    #[test]
    fn test_decrypt_str_or_original_non_ascii_prefix_does_not_panic() {
        use super::*;

        let data = "中a";
        let (decrypted, succ, store) = decrypt_str_or_original(data, VERSION_02_USER);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);
    }

    #[test]
    fn test_version_02_magic_header_detection() {
        use super::*;

        let payload = b"payload".to_vec();
        assert!(!crate::secret_store::user_data_has_magic_header(&payload));
        assert!(!is_encrypted(
            format!(
                "{VERSION_02_USER}{}",
                base64::encode(&payload, base64::Variant::Original)
            )
            .as_bytes(),
            true
        ));

        let current_payload = crate::secret_store::user_data_add_magic_header(payload.clone());
        assert!(crate::secret_store::user_data_has_magic_header(
            &current_payload
        ));

        let encoded = base64::encode(&current_payload, base64::Variant::Original);
        let versioned = format!("{VERSION_02_USER}{encoded}");
        assert!(is_encrypted(versioned.as_bytes(), true));
        assert!(!should_store_after_decrypt(
            VERSION_02_USER,
            &payload,
            VERSION_02_USER,
            true
        ));
    }

    #[test]
    fn test_version_02_encrypted_payload_has_magic_header() {
        use super::*;
        use sodiumoxide::base64::{decode, Variant};

        let encrypted = encrypt_str_or_original("1", VERSION_02_USER, 128);
        let payload = decode(&encrypted.as_bytes()[VERSION_LEN..], Variant::Original).unwrap();
        assert!(crate::secret_store::user_data_has_magic_header(&payload));
    }

    #[test]
    fn test_version_02_vec_uses_raw_payload() {
        use super::*;

        let encrypted = encrypt_vec_or_original(b"1", VERSION_02_USER, 128);
        let payload = &encrypted[VERSION_LEN..];
        assert!(crate::secret_store::user_data_has_magic_header(payload));
        assert!(is_encrypted(&encrypted, false));
    }

    #[test]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn test_decrypt_with_pk_fallback() {
        use super::*;
        use sodiumoxide::crypto::secretbox;
        use std::convert::TryInto;

        let uuid = crate::get_uuid();
        let pk = crate::config::Config::get_key_pair().1;

        if uuid == pk {
            eprintln!("skip: uuid == pk, fallback branch won't be tested");
            return;
        }

        let data = b"test password 123";
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

        let mut pk_keybuf = pk;
        pk_keybuf.resize(secretbox::KEYBYTES, 0);
        let pk_key = secretbox::Key(pk_keybuf.try_into().unwrap());
        let encrypted = secretbox::seal(data, &nonce, &pk_key);

        let decrypted = symmetric_crypt_00_uuid(&encrypted, false);
        assert!(decrypted.is_ok(), "Decryption with pk fallback should succeed");
        assert_eq!(decrypted.unwrap(), data);
    }

    #[test]
    fn test_version_00_cross_version_compatibility() {
        use super::*;

        let max_len = 128;

        let old_encoded_str = encrypt_str_or_original("old-to-new", VERSION_00_UUID, max_len);
        assert_eq!(&old_encoded_str[..VERSION_LEN], VERSION_00_UUID);
        let (decrypted, succ, store) =
            decrypt_str_or_original(&old_encoded_str, VERSION_02_USER);
        assert_eq!(decrypted, "old-to-new");
        assert!(succ);
        assert!(store);

        let new_encoded_str = encrypt_str_or_original("new-to-old", VERSION_00_UUID, max_len);
        assert_eq!(&new_encoded_str[..VERSION_LEN], VERSION_00_UUID);
        let (decrypted, succ, store) =
            decrypt_str_or_original(&new_encoded_str, VERSION_00_UUID);
        assert_eq!(decrypted, "new-to-old");
        assert!(succ);
        assert!(!store);

        let old_encoded_vec = encrypt_vec_or_original(b"old-to-new-vec", VERSION_00_UUID, max_len);
        assert_eq!(&old_encoded_vec[..VERSION_LEN], VERSION_00_UUID.as_bytes());
        let (decrypted, succ, store) =
            decrypt_vec_or_original(&old_encoded_vec, VERSION_02_USER);
        assert_eq!(decrypted, b"old-to-new-vec");
        assert!(succ);
        assert!(store);

        let new_encoded_vec = encrypt_vec_or_original(b"new-to-old-vec", VERSION_00_UUID, max_len);
        assert_eq!(&new_encoded_vec[..VERSION_LEN], VERSION_00_UUID.as_bytes());
        let (decrypted, succ, store) =
            decrypt_vec_or_original(&new_encoded_vec, VERSION_00_UUID);
        assert_eq!(decrypted, b"new-to-old-vec");
        assert!(succ);
        assert!(!store);
    }
}

// Manual verification checklist for version 02 system-user encryption:
// 1. Verify encrypted data can still be decrypted after uninstalling and
//    reinstalling the app under the same OS user.
// 2. Verify encrypted data can still be decrypted after a system reboot.
// 3. Verify re-encrypting the same plaintext produces different ciphertext due
//    to the random nonce, but this alone does not mark the current version 02
//    payload for migration or trigger an extra store on load.
// 4. Verify version 00 compatibility across releases: data encrypted by an old
//    build can be decrypted by a new build, and data encrypted by a new build
//    with version 00 can still be decrypted by an old build.
