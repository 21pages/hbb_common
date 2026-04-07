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
pub const VERSION_02_SYSTEM_USER: &str = "02";

// Check if data is already encrypted by verifying:
// 1) known version prefix
// 2) valid base64 payload
// 3) decoded payload length >= minimum payload size for that version
//
// We intentionally avoid trying to decrypt here because key mismatch would cause
// false negatives.
// Reference: secretbox::seal returns ciphertext length = plaintext length + MACBYTES
// https://github.com/sodiumoxide/sodiumoxide/blob/3057acb1a030ad86ed8892a223d64036ab5e8523/src/crypto/secretbox/xsalsa20poly1305.rs#L67
fn is_encrypted(v: &[u8]) -> bool {
    if v.len() <= VERSION_LEN {
        return false;
    }
    let min_len = if v.starts_with(VERSION_00_UUID.as_bytes()) {
        sodiumoxide::crypto::secretbox::MACBYTES
    } else if v.starts_with(VERSION_02_SYSTEM_USER.as_bytes()) {
        sodiumoxide::crypto::secretbox::NONCEBYTES + sodiumoxide::crypto::secretbox::MACBYTES
    } else {
        return false;
    };
    match base64::decode(&v[VERSION_LEN..], base64::Variant::Original) {
        Ok(decoded) => decoded.len() >= min_len,
        Err(_) => false,
    }
}

pub fn encrypt_str_or_original(s: &str, version: &str, max_len: usize) -> String {
    if is_encrypted(s.as_bytes()) {
        log::error!("Duplicate encryption!");
        return s.to_owned();
    }
    if s.chars().count() > max_len {
        return String::default();
    }
    if let Ok(s) = encrypt(s.as_bytes(), version) {
        return version.to_owned() + &s;
    }
    s.to_owned()
}

fn known_version_prefix(v: &[u8]) -> Option<&str> {
    if v.len() <= VERSION_LEN {
        return None;
    }
    if v.starts_with(VERSION_00_UUID.as_bytes()) {
        Some(VERSION_00_UUID)
    } else if v.starts_with(VERSION_02_SYSTEM_USER.as_bytes()) {
        Some(VERSION_02_SYSTEM_USER)
    } else {
        None
    }
}

// String: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
// note: s.len() return length in bytes, s.chars().count() return char count
//       avoid slicing `&str` by raw byte offsets unless the boundary is known-valid UTF-8
pub fn decrypt_str_or_original(s: &str, current_version: &str) -> (String, bool, bool) {
    if let Some(version) = known_version_prefix(s.as_bytes()) {
        if let Ok(v) = decrypt(s[VERSION_LEN..].as_bytes(), version) {
            return (
                String::from_utf8_lossy(&v).to_string(),
                true,
                version != current_version,
            );
        }
    }

    // For values that already look encrypted (version prefix + base64), avoid
    // repeated store on each load when decryption fails.
    (
        s.to_owned(),
        false,
        !s.is_empty() && !is_encrypted(s.as_bytes()),
    )
}

pub fn encrypt_vec_or_original(v: &[u8], version: &str, max_len: usize) -> Vec<u8> {
    if is_encrypted(v) {
        log::error!("Duplicate encryption!");
        return v.to_owned();
    }
    if v.len() > max_len {
        return vec![];
    }
    if let Ok(s) = encrypt(v, version) {
        let mut version = version.to_owned().into_bytes();
        version.append(&mut s.into_bytes());
        return version;
    }
    v.to_owned()
}

// Vec<u8>: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
pub fn decrypt_vec_or_original(v: &[u8], current_version: &str) -> (Vec<u8>, bool, bool) {
    if let Some(version) = known_version_prefix(v) {
        if let Ok(v) = decrypt(&v[VERSION_LEN..], version) {
            return (v, true, version != current_version);
        }
    }

    // For values that already look encrypted (version prefix + base64), avoid
    // repeated store on each load when decryption fails.
    (v.to_owned(), false, !v.is_empty() && !is_encrypted(v))
}

pub fn encrypt_raw_with_version(data: &[u8], version: &str) -> Result<Vec<u8>, ()> {
    let mut out = version.as_bytes().to_vec();
    out.extend(encrypt_raw(data, version)?);
    Ok(out)
}

pub fn decrypt_raw_with_version_or_original(
    data: &[u8],
    current_version: &str,
) -> (Vec<u8>, bool, bool) {
    if let Some(version) = known_version_prefix(data) {
        if let Ok(v) = decrypt_raw(&data[VERSION_LEN..], version) {
            return (v, true, version != current_version);
        }
    }
    (data.to_owned(), false, false)
}

fn encrypt(v: &[u8], version: &str) -> Result<String, ()> {
    if !v.is_empty() {
        encrypt_raw(v, version).map(|v| base64::encode(v, base64::Variant::Original))
    } else {
        Err(())
    }
}

fn decrypt(v: &[u8], version: &str) -> Result<Vec<u8>, ()> {
    if !v.is_empty() {
        base64::decode(v, base64::Variant::Original).and_then(|v| decrypt_raw(&v, version))
    } else {
        Err(())
    }
}

fn encrypt_raw(data: &[u8], version: &str) -> Result<Vec<u8>, ()> {
    match version {
        VERSION_00_UUID => symmetric_crypt_00_uuid(data, true),
        VERSION_02_SYSTEM_USER => symmetric_crypt_02_system_user(data, true),
        _ => Err(()),
    }
}

fn decrypt_raw(data: &[u8], version: &str) -> Result<Vec<u8>, ()> {
    match version {
        VERSION_00_UUID => symmetric_crypt_00_uuid(data, false),
        VERSION_02_SYSTEM_USER => symmetric_crypt_02_system_user(data, false),
        _ => Err(()),
    }
}

fn symmetric_crypt_00_uuid(data: &[u8], encrypt: bool) -> Result<Vec<u8>, ()> {
    use sodiumoxide::crypto::secretbox;
    use std::convert::TryInto;

    let uuid = crate::get_uuid();
    let mut keybuf = uuid.clone();
    keybuf.resize(secretbox::KEYBYTES, 0);
    let key = secretbox::Key(keybuf.try_into().map_err(|_| ())?);
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
                    let pk_key = secretbox::Key(keybuf.try_into().map_err(|_| ())?);
                    return secretbox::open(data, &nonce, &pk_key);
                }
            }
        }
        res
    }
}

// Version 02 uses the system/user-scoped master key. During decryption it
// falls back to version 00 for compatibility with unversioned stored payloads.
pub fn symmetric_crypt_02_system_user(data: &[u8], encrypt: bool) -> Result<Vec<u8>, ()> {
    use sodiumoxide::crypto::secretbox;
    use std::convert::TryInto;

    let keybuf = crate::secret_store::get_or_create_master_key().map_err(|_| ())?;
    let key = secretbox::Key(keybuf.try_into().map_err(|_| ())?);

    if encrypt {
        let nonce = secretbox::gen_nonce();
        let mut out = nonce.0.to_vec();
        out.extend(secretbox::seal(data, &nonce, &key));
        Ok(out)
    } else {
        if data.len() >= secretbox::NONCEBYTES + secretbox::MACBYTES {
            let nonce = secretbox::Nonce(data[..secretbox::NONCEBYTES].try_into().map_err(|_| ())?);
            if let Ok(v) = secretbox::open(&data[secretbox::NONCEBYTES..], &nonce, &key) {
                return Ok(v);
            }
        }
        symmetric_crypt_00_uuid(data, false)
    }
}

mod test {

    #[test]
    fn test() {
        use super::*;
        use rand::{thread_rng, Rng};
        use std::time::Instant;

        let version_system_user = VERSION_02_SYSTEM_USER;
        let version_uuid = VERSION_00_UUID;
        let max_len = 128;

        println!("test str");
        let data = "1ü1111";
        let encrypted = encrypt_str_or_original(data, version_system_user, max_len);
        let (decrypted, succ, store) = decrypt_str_or_original(&encrypted, version_system_user);
        println!("data: {data}");
        println!("encrypted: {encrypted}");
        println!("decrypted: {decrypted}");
        assert_eq!(data, decrypted);
        assert_eq!(version_system_user, &encrypted[..2]);
        assert!(succ);
        assert!(!store);
        let (_, _, store) = decrypt_str_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_str_or_original(&decrypted, version_system_user).1);
        assert_eq!(
            encrypt_str_or_original(&encrypted, version_system_user, max_len),
            encrypted
        );

        println!("test vec");
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        let encrypted = encrypt_vec_or_original(&data, version_system_user, max_len);
        let (decrypted, succ, store) = decrypt_vec_or_original(&encrypted, version_system_user);
        println!("data: {data:?}");
        println!("encrypted: {encrypted:?}");
        println!("decrypted: {decrypted:?}");
        assert_eq!(data, decrypted);
        assert_eq!(version_system_user.as_bytes(), &encrypted[..2]);
        assert!(!store);
        assert!(succ);
        let (_, _, store) = decrypt_vec_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_vec_or_original(&decrypted, version_system_user).1);
        assert_eq!(
            encrypt_vec_or_original(&encrypted, version_system_user, max_len),
            encrypted
        );

        println!("test original");
        let data = version_system_user.to_string() + "Hello World";
        let (decrypted, succ, store) = decrypt_str_or_original(&data, version_system_user);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let verbytes = version_system_user.as_bytes();
        let data: Vec<u8> = vec![verbytes[0], verbytes[1], 1, 2, 3, 4, 5, 6];
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version_system_user);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let (_, succ, store) = decrypt_str_or_original("", version_system_user);
        assert!(!store);
        assert!(!succ);
        let (_, succ, store) = decrypt_vec_or_original(&[], version_system_user);
        assert!(!store);
        assert!(!succ);
        let data = "1ü1111";
        assert_eq!(decrypt_str_or_original(data, version_system_user).0, data);
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        assert_eq!(decrypt_vec_or_original(&data, version_system_user).0, data);

        println!("test version 00 compatibility");
        let legacy_encrypted = encrypt_str_or_original("legacy", version_uuid, max_len);
        let (legacy_decrypted, succ, store) =
            decrypt_str_or_original(&legacy_encrypted, version_system_user);
        assert_eq!(legacy_decrypted, "legacy");
        assert!(succ);
        assert!(store);

        // Base64-shaped "00" prefixed values shorter than MACBYTES are treated
        // as original/plain values and should be stored.
        let data = "00YWJjZA==";
        let (decrypted, succ, store) = decrypt_str_or_original(data, version_system_user);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);
        let data = b"00YWJjZA==".to_vec();
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version_system_user);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);

        // When decoded length reaches MACBYTES, it is treated as encrypted-like
        // and should not trigger repeated store.
        let exact_mac = vec![0u8; sodiumoxide::crypto::secretbox::MACBYTES];
        let exact_mac_b64 =
            sodiumoxide::base64::encode(&exact_mac, sodiumoxide::base64::Variant::Original);
        let data = format!("00{exact_mac_b64}");
        let (_, succ, store) = decrypt_str_or_original(&data, version_system_user);
        assert!(!succ);
        assert!(!store);
        let data = data.into_bytes();
        let (_, succ, store) = decrypt_vec_or_original(&data, version_system_user);
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
            let encrypted = encrypt_vec_or_original(&data, version_system_user, len);
            assert_ne!(data, decrypted);
            let t1 = start.elapsed();
            let start = Instant::now();
            let (decrypted, _, _) = decrypt_vec_or_original(&encrypted, version_system_user);
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
        assert!(!is_encrypted(b""));
        assert!(!is_encrypted(b"0"));
        assert!(!is_encrypted(b"00"));

        // Data without "00" prefix should not be considered encrypted
        assert!(!is_encrypted(b"01abcd"));
        assert!(!is_encrypted(b"99abcd"));
        assert!(!is_encrypted(b"hello world"));

        // Data with "00" prefix but invalid base64 should not be considered encrypted
        assert!(!is_encrypted(b"00!!!invalid base64!!!"));
        assert!(!is_encrypted(b"00@#$%"));

        // Data with "00" prefix and valid base64 but shorter than MACBYTES is not encrypted
        assert!(!is_encrypted(b"00YWJjZA==")); // "abcd" in base64
        assert!(!is_encrypted(b"00SGVsbG8gV29ybGQ=")); // "Hello World" in base64

        // Data with "00" prefix and valid base64 with decoded len == MACBYTES is considered encrypted
        let exact_mac = vec![0u8; secretbox::MACBYTES];
        let exact_mac_b64 = encode(&exact_mac, Variant::Original);
        let exact_mac_candidate = format!("00{exact_mac_b64}");
        assert!(is_encrypted(exact_mac_candidate.as_bytes()));

        // Real encrypted data should be detected
        let version_uuid = VERSION_00_UUID;
        let max_len = 128;
        let encrypted_str = encrypt_str_or_original("1", version_uuid, max_len);
        assert!(is_encrypted(encrypted_str.as_bytes()));
        let encrypted_vec = encrypt_vec_or_original(b"1", version_uuid, max_len);
        assert!(is_encrypted(&encrypted_vec));

        // Original unencrypted data should not be detected as encrypted
        assert!(!is_encrypted(b"1"));
        assert!(!is_encrypted("1".as_bytes()));
    }

    #[test]
    fn test_encrypted_payload_min_len_macbytes() {
        use super::*;
        use sodiumoxide::base64::{decode, Variant};
        use sodiumoxide::crypto::secretbox;

        let version_user_scope = VERSION_02_SYSTEM_USER;
        let max_len = 128;

        let encrypted_str = encrypt_str_or_original("1", version_user_scope, max_len);
        let decoded = decode(&encrypted_str.as_bytes()[VERSION_LEN..], Variant::Original).unwrap();
        assert!(
            decoded.len() >= secretbox::MACBYTES,
            "decoded encrypted payload must be at least MACBYTES"
        );

        let encrypted_vec = encrypt_vec_or_original(b"1", version_user_scope, max_len);
        let decoded = decode(&encrypted_vec[VERSION_LEN..], Variant::Original).unwrap();
        assert!(
            decoded.len() >= secretbox::MACBYTES,
            "decoded encrypted payload must be at least MACBYTES"
        );
    }

    #[test]
    fn test_decrypt_str_or_original_non_ascii_prefix_does_not_panic() {
        use super::*;

        let data = "中a";
        let (decrypted, succ, store) = decrypt_str_or_original(data, VERSION_02_SYSTEM_USER);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);
    }

    #[test]
    fn test_raw_versioned_roundtrip() {
        use super::*;

        let version_user_scope = VERSION_02_SYSTEM_USER;
        let version_uuid = VERSION_00_UUID;
        let data = b"raw payload";

        let encrypted = encrypt_raw_with_version(data, version_user_scope).unwrap();
        let (decrypted, succ, store) =
            decrypt_raw_with_version_or_original(&encrypted, version_user_scope);
        assert_eq!(decrypted, data);
        assert!(succ);
        assert!(!store);

        let legacy = encrypt_raw_with_version(data, version_uuid).unwrap();
        let (decrypted, succ, store) =
            decrypt_raw_with_version_or_original(&legacy, version_user_scope);
        assert_eq!(decrypted, data);
        assert!(succ);
        assert!(store);
    }

    // Test decryption fallback when data was encrypted with key_pair but decryption tries machine_uid first.
    #[test]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn test_decrypt_with_pk_fallback() {
        use sodiumoxide::crypto::secretbox;
        use std::convert::TryInto;

        let uuid = crate::get_uuid();
        let pk = crate::config::Config::get_key_pair().1;

        // Ensure uuid != pk, otherwise fallback branch won't be tested
        if uuid == pk {
            eprintln!("skip: uuid == pk, fallback branch won't be tested");
            return;
        }

        let data = b"test password 123";
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

        // Encrypt with pk (simulating machine_uid failure during encryption)
        let mut pk_keybuf = pk;
        pk_keybuf.resize(secretbox::KEYBYTES, 0);
        let pk_key = secretbox::Key(pk_keybuf.try_into().unwrap());
        let encrypted = secretbox::seal(data, &nonce, &pk_key);

        // Decrypt using version 02 path; it should fallback to pk since uuid differs.
        let decrypted = super::symmetric_crypt_02_system_user(&encrypted, false);
        assert!(
            decrypted.is_ok(),
            "Decryption with pk fallback should succeed"
        );
        assert_eq!(decrypted.unwrap(), data);
    }
}
