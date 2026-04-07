use crate::config::APP_NAME;
use core_foundation::{
    base::{CFTypeRef, TCFType, ToVoid},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFMutableDictionary,
    error::CFError,
    number::CFNumber,
    string::{CFString, CFStringRef},
};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    base::Error as SecurityError,
    item::{ItemSearchOptions, KeyClass, Reference, SearchResult},
    key::{Algorithm, SecKey},
};
use security_framework_sys::{
    base::{errSecItemNotFound, errSecSuccess},
    item::{
        kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPrivate,
        kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeRSA, kSecAttrLabel, kSecClass,
        kSecClassKey, kSecPrivateKeyAttrs, kSecReturnRef,
    },
    key::SecKeyCreateRandomKey,
    keychain_item::SecItemCopyMatching,
};
#[cfg(target_os = "macos")]
use security_framework_sys::item::kSecUseDataProtectionKeychain;
use std::ptr;

use super::{SecretStoreError, SecretStoreResult};
const APPLE_CRYPTO_ROOT_LABEL_SUFFIX: &str = ".crypto-root.02";

extern "C" {
    // `kSecAttrApplicationTag` stores an app-defined tag for later key lookup.
    // Apple docs:
    // https://developer.apple.com/documentation/security/key-generation-attributes
    // https://developer.apple.com/documentation/security/getting-an-existing-key
    static kSecAttrApplicationTag: CFStringRef;
}

fn apple_crypto_root_label() -> String {
    format!(
        "{}{}",
        APP_NAME.read().unwrap().clone(),
        APPLE_CRYPTO_ROOT_LABEL_SUFFIX
    )
}

#[cfg(target_os = "macos")]
fn apple_crypto_root_enable_data_protection_keychain(query: &mut CFMutableDictionary) {
    // On macOS, this opt-in switches the query to the Data Protection
    // keychain so new macOS keys behave like the iOS-protected keychain path.
    //
    // Apple docs:
    // https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
    // https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains
    query.set(
        unsafe { kSecUseDataProtectionKeychain }.to_void(),
        CFBoolean::true_value().to_void(),
    );
}

#[cfg(target_os = "ios")]
fn apple_crypto_root_enable_data_protection_keychain(_query: &mut CFMutableDictionary) {
}

fn apple_crypto_root_access_control() -> SecretStoreResult<SecAccessControl> {
    // `SecAccessControl::create_with_protection(...)` wraps
    // `SecAccessControlCreateWithFlags(...)`.
    //
    // We intentionally use the same protection on both macOS and iOS:
    // `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
    //
    // This keeps the key usable only while the device is unlocked and makes
    // the crypto root device-bound.
    // Apple docs:
    // https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags%28_%3A_%3A_%3A_%3A%29
    // https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility
    // https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked
    // https://developer.apple.com/documentation/security/ksecattraccessible
    SecAccessControl::create_with_protection(
        Some(apple_crypto_root_protection_mode()),
        Default::default(),
    )
    .map_err(|err| {
        SecretStoreError::backend("failed to create Apple crypto root access control", err)
    })
}

fn apple_crypto_root_protection_mode() -> ProtectionMode {
    ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly
}

fn find_apple_crypto_root_key_by_label(label: &str) -> SecretStoreResult<Option<SecKey>> {
    // Legacy fallback for older macOS installs that created the key in the
    // default file-based keychain and can only be found by label.
    //
    // `ItemSearchOptions::search()` wraps `SecItemCopyMatching(...)`.
    //
    // This query asks Keychain Services for:
    // - a private key (`kSecAttrKeyClass = kSecAttrKeyClassPrivate`)
    // - matching the human-readable label (`kSecAttrLabel`)
    // - returned as a live `SecKeyRef` (`kSecReturnRef = true`)
    //
    // Apple docs:
    // https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29
    // https://developer.apple.com/documentation/security/getting-an-existing-key
    // https://developer.apple.com/documentation/security/ksecreturnref
    let mut search = ItemSearchOptions::new();
    search
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true);
    let results = match search.search() {
        Ok(results) => results,
        Err(err) if err.code() == errSecItemNotFound => return Ok(None),
        Err(err) => {
            return Err(SecretStoreError::backend(
                "failed to search Apple crypto root key",
                err,
            ))
        }
    };
    for result in results {
        if let SearchResult::Ref(Reference::Key(key)) = result {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

fn find_apple_crypto_root_key_by_application_tag(tag: &[u8]) -> SecretStoreResult<Option<SecKey>> {
    // Permanent keys are primarily retrieved by
    // `kSecAttrApplicationTag` with `SecItemCopyMatching(...)`.
    // The query below means:
    // - `kSecClass = kSecClassKey`: search key items
    // - `kSecAttrKeyClass = kSecAttrKeyClassPrivate`: only private keys
    // - `kSecReturnRef = true`: return a `SecKeyRef`
    // - `kSecAttrApplicationTag = tag`: match our stable app-defined tag
    //
    // Apple docs:
    // https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29
    // https://developer.apple.com/documentation/security/getting-an-existing-key
    // https://developer.apple.com/documentation/security/keychain-items
    // https://developer.apple.com/documentation/security/ksecclasskey
    // https://developer.apple.com/documentation/security/ksecattrkeyclass
    // https://developer.apple.com/documentation/security/ksecreturnref
    let tag = CFData::from_buffer(tag);
    let mut query = CFMutableDictionary::from_CFType_pairs(&[
        (unsafe { kSecClass }.to_void(), unsafe { kSecClassKey }.to_void()),
        (
            unsafe { kSecAttrKeyClass }.to_void(),
            unsafe { kSecAttrKeyClassPrivate }.to_void(),
        ),
        (
            unsafe { kSecReturnRef }.to_void(),
            CFBoolean::true_value().to_void(),
        ),
        (unsafe { kSecAttrApplicationTag }.to_void(), tag.to_void()),
    ]);
    apple_crypto_root_enable_data_protection_keychain(&mut query);

    let mut item: CFTypeRef = ptr::null();
    let status = unsafe { SecItemCopyMatching(query.to_immutable().as_concrete_TypeRef(), &mut item) };
    if status == errSecSuccess {
        if item.is_null() {
            return Ok(None);
        }
        let key = unsafe { SecKey::wrap_under_create_rule(item as *mut _) };
        Ok(Some(key))
    } else if status == errSecItemNotFound {
        Ok(None)
    } else {
        Err(SecretStoreError::backend_message(
            "failed to search Apple crypto root key",
            SecurityError::from_code(status).to_string(),
        ))
    }
}

fn find_apple_crypto_root_key(label: &str) -> SecretStoreResult<Option<SecKey>> {
    if let Some(key) = find_apple_crypto_root_key_by_application_tag(label.as_bytes())? {
        return Ok(Some(key));
    }
    // Compatibility fallback so existing macOS installs keep using the legacy
    // key instead of silently generating a new root and breaking decryption of
    // already-encrypted data.
    find_apple_crypto_root_key_by_label(label)
}

fn create_apple_crypto_root_key(label: &str) -> SecretStoreResult<SecKey> {
    // `SecKeyCreateRandomKey(...)` creates a key pair from an attribute
    // dictionary. The attributes below intentionally use:
    // - `kSecAttrKeyType = kSecAttrKeyTypeRSA`: RSA key pair
    // - `kSecAttrKeySizeInBits = 2048`: 2048-bit RSA modulus
    // - `kSecAttrLabel`: human-readable label for inspection / fallback lookup
    // - `kSecPrivateKeyAttrs`: private-key-specific attributes
    // - `kSecAttrIsPermanent = true`: persist the key in the keychain
    // - `kSecAttrAccessControl`: attach the accessibility policy created above
    // - `kSecAttrApplicationTag`: stable app-defined lookup tag on both Apple
    //   platforms
    //
    // On macOS we additionally set `kSecUseDataProtectionKeychain = true` so
    // new keys use the same protected keychain model as iOS.
    //
    // Apple docs:
    // https://developer.apple.com/documentation/security/seckeycreaterandomkey%28_%3A_%3A%29
    // https://developer.apple.com/documentation/security/key-generation-attributes
    // https://developer.apple.com/documentation/security/ksecattraccesscontrol
    // https://developer.apple.com/documentation/security/getting-an-existing-key
    let access_control = apple_crypto_root_access_control()?;
    let label_string = CFString::new(label);
    let tag = CFData::from_buffer(label.as_bytes());
    let key_size = CFNumber::from(2048);
    let is_permanent = CFBoolean::true_value();

    let private_attributes = CFMutableDictionary::from_CFType_pairs(&[
        (
            unsafe { kSecAttrIsPermanent }.to_void(),
            is_permanent.to_void(),
        ),
        (
            unsafe { kSecAttrAccessControl }.to_void(),
            access_control.to_void(),
        ),
        (
            unsafe { kSecAttrApplicationTag }.to_void(),
            tag.to_void(),
        ),
    ])
    .to_immutable();

    let mut attributes = CFMutableDictionary::from_CFType_pairs(&[
        (
            unsafe { kSecAttrKeyType }.to_void(),
            unsafe { kSecAttrKeyTypeRSA }.to_void(),
        ),
        (
            unsafe { kSecAttrKeySizeInBits }.to_void(),
            key_size.to_void(),
        ),
        (unsafe { kSecAttrLabel }.to_void(), label_string.to_void()),
        (
            unsafe { kSecPrivateKeyAttrs }.to_void(),
            private_attributes.to_void(),
        ),
    ]);
    apple_crypto_root_enable_data_protection_keychain(&mut attributes);
    let attributes = attributes.to_immutable();

    let mut error = ptr::null_mut();
    let key = unsafe { SecKeyCreateRandomKey(attributes.as_concrete_TypeRef(), &mut error) };
    if error.is_null() {
        Ok(unsafe { SecKey::wrap_under_create_rule(key) })
    } else {
        Err(SecretStoreError::backend_message(
            "failed to create Apple crypto root key",
            unsafe { CFError::wrap_under_create_rule(error) }.to_string(),
        ))
    }
}

fn get_or_create_apple_crypto_root_key() -> SecretStoreResult<SecKey> {
    let label = apple_crypto_root_label();
    if let Some(key) = find_apple_crypto_root_key(&label)? {
        return Ok(key);
    }
    create_apple_crypto_root_key(&label)
}

pub fn encrypt_user_data(data: &[u8]) -> SecretStoreResult<Vec<u8>> {
    // `SecKey::public_key()` wraps `SecKeyCopyPublicKey(...)`.
    // `encrypt_data(...)` wraps `SecKeyCreateEncryptedData(...)`.
    //
    // Important: `RSAEncryptionOAEPSHA256AESGCM` is not "raw RSA encrypt the
    // whole plaintext". Apple defines it as a hybrid scheme:
    // - generate a random AES session key
    // - wrap that session key with RSA-OAEP-SHA256
    // - encrypt the user data with AES-GCM
    //
    // That means it can encrypt arbitrary-length user data and does not have
    // the usual RSA-2048 OAEP payload limit of about 190 bytes.
    // Apple docs:
    // https://developer.apple.com/documentation/security/seckeycopypublickey%28_%3A%29
    // https://developer.apple.com/documentation/security/seckeycreateencrypteddata%28_%3A_%3A_%3A_%3A%29
    // https://developer.apple.com/documentation/security/seckeyalgorithm/rsaencryptionoaepsha256aesgcm
    // https://developer.apple.com/documentation/security/using-keys-for-encryption
    let private_key = get_or_create_apple_crypto_root_key()?;
    let public_key = private_key.public_key().ok_or_else(|| {
        SecretStoreError::backend_message(
            "failed to access Apple crypto root public key",
            "SecKeyCopyPublicKey returned null",
        )
    })?;
    public_key
        .encrypt_data(Algorithm::RSAEncryptionOAEPSHA256AESGCM, data)
        .map_err(|err| {
            SecretStoreError::backend_message(
                "failed to encrypt data with Apple crypto root",
                err.to_string(),
            )
        })
}

pub fn decrypt_user_data(data: &[u8]) -> SecretStoreResult<Vec<u8>> {
    // `decrypt_data(...)` wraps `SecKeyCreateDecryptedData(...)` and expects
    // ciphertext produced by the matching
    // `kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM` hybrid format above.
    // Apple docs:
    // https://developer.apple.com/documentation/security/seckeycreatedecrypteddata%28_%3A_%3A_%3A_%3A%29
    // https://developer.apple.com/documentation/security/seckeyalgorithm/rsaencryptionoaepsha256aesgcm
    // https://developer.apple.com/documentation/security/using-keys-for-encryption
    let private_key = get_or_create_apple_crypto_root_key()?;
    private_key
        .decrypt_data(Algorithm::RSAEncryptionOAEPSHA256AESGCM, data)
        .map_err(|err| {
            SecretStoreError::backend_message(
                "failed to decrypt data with Apple crypto root",
                err.to_string(),
            )
        })
}
