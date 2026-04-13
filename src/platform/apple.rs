use crate::secret_store::{SecretStoreError, SecretStoreResult};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    passwords::{
        generic_password, set_generic_password, set_generic_password_options, PasswordOptions,
    },
};

// errSecItemNotFound from Apple Security Framework (defined in SecBase.h)
// https://developer.apple.com/documentation/security/1542001-security_framework_result_codes
// https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/base/SecBase.h#L353
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

pub(crate) fn map_keychain_result<T>(
    result: security_framework::base::Result<T>,
    context: &'static str,
) -> SecretStoreResult<T> {
    match result {
        Ok(value) => Ok(value),
        Err(err) if err.code() == ERR_SEC_ITEM_NOT_FOUND => Err(SecretStoreError::NotFound),
        Err(err) => Err(SecretStoreError::backend(context, err)),
    }
}

pub fn load_secret_keychain_generic(service: &str, account: &str) -> SecretStoreResult<Vec<u8>> {
    // Apple Security.framework refs used by `security-framework::passwords::generic_password`:
    // - SecItemCopyMatching(...)
    //   https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29
    crate::log::info!(
        "==== apple load_secret_keychain_generic service={} account={}",
        service,
        account
    );
    let result = map_keychain_result(
        generic_password(PasswordOptions::new_generic_password(service, account)),
        "failed to read secret from Apple generic keychain",
    );
    match &result {
        Ok(data) => crate::log::info!(
            "==== apple load_secret_keychain_generic success, secret_len={} secret_hex={}",
            data.len(),
            crate::platform::bytes_to_hex(data)
        ),
        Err(err) => crate::log::error!("==== apple load_secret_keychain_generic failed: {:?}", err),
    }
    result
}

pub fn store_secret_keychain_generic(
    service: &str,
    account: &str,
    secret: &[u8],
) -> SecretStoreResult<()> {
    // Apple Security.framework refs used by `security-framework::passwords::set_generic_password`:
    // - SecItemAdd(...)
    //   https://developer.apple.com/documentation/security/secitemadd%28_%3A_%3A%29
    // - SecItemUpdate(...)
    //   https://developer.apple.com/documentation/security/secitemupdate%28_%3A_%3A%29
    crate::log::info!(
        "==== apple store_secret_keychain_generic service={} account={} secret_len={} secret_hex={}",
        service,
        account,
        secret.len(),
        crate::platform::bytes_to_hex(secret)
    );
    let result = map_keychain_result(
        set_generic_password(service, account, secret),
        "failed to write secret to Apple generic keychain",
    );
    match &result {
        Ok(_) => crate::log::info!("==== apple store_secret_keychain_generic success"),
        Err(err) => {
            crate::log::error!("==== apple store_secret_keychain_generic failed: {:?}", err)
        }
    }
    result?;
    Ok(())
}

/// Read a generic password from Apple's Data Protection Keychain.
///
/// This is the store selected by `kSecUseDataProtectionKeychain`, not the
/// traditional login keychain. On iOS this is the normal secret store, but on
/// macOS it has stricter runtime requirements:
///
/// - the caller is expected to be an app-style signed process running in a
///   user session, not an arbitrary command-line binary;
/// - depending on how the app is packaged, the process may also need validated
///   entitlements and provisioning-profile-backed capabilities;
/// - if these conditions are not met, Security.framework commonly returns
///   `errSecNotAvailable` instead of reading from the legacy keychain.
///
/// In other words, a successful read here depends on the process environment,
/// not only on the `(service, account)` pair. macOS callers that want the
/// legacy keychain should use the generic helpers instead.
pub fn load_secret_keychain_protected(service: &str, account: &str) -> SecretStoreResult<Vec<u8>> {
    // Apple Security.framework refs:
    // - kSecUseDataProtectionKeychain
    //   https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
    // - SecItemCopyMatching(...)
    //   https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29
    crate::log::info!(
        "==== apple load_secret_keychain_protected service={} account={}",
        service,
        account
    );
    let mut options = PasswordOptions::new_generic_password(service, account);
    options.use_protected_keychain();
    let result = map_keychain_result(
        generic_password(options),
        "failed to read secret from Apple protected keychain",
    );
    match &result {
        Ok(data) => crate::log::info!(
            "==== apple load_secret_keychain_protected success, secret_len={} secret_hex={}",
            data.len(),
            crate::platform::bytes_to_hex(data)
        ),
        Err(err) => crate::log::error!(
            "==== apple load_secret_keychain_protected failed: {:?}",
            err
        ),
    }
    result
}

/// Write a generic password into Apple's Data Protection Keychain.
///
/// The access control attached here matches iOS-style protected storage
/// semantics, but on macOS the main precondition is still that the current
/// process is allowed to use the Data Protection Keychain at all. If the
/// process is an ordinary CLI tool, unsigned helper, daemon, or otherwise lacks
/// the required signing / entitlement context, the write can fail before the
/// access-control settings matter.
///
/// This is why the default macOS secret-store path in `platform/macos.rs` does
/// not call this function and instead uses the traditional login keychain.
pub fn store_secret_keychain_protected(
    service: &str,
    account: &str,
    secret: &[u8],
) -> SecretStoreResult<()> {
    // Apple Security.framework refs:
    // - kSecUseDataProtectionKeychain
    //   https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
    // - SecAccessControlCreateWithFlags(...)
    //   https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags%28_%3A_%3A_%3A_%3A%29
    // - SecItemAdd(...)
    //   https://developer.apple.com/documentation/security/secitemadd%28_%3A_%3A%29
    // - SecItemUpdate(...)
    //   https://developer.apple.com/documentation/security/secitemupdate%28_%3A_%3A%29
    crate::log::info!(
        "==== apple store_secret_keychain_protected service={} account={} secret_len={} secret_hex={}",
        service,
        account,
        secret.len(),
        crate::platform::bytes_to_hex(secret)
    );
    let mut options = PasswordOptions::new_generic_password(service, account);
    options.use_protected_keychain();
    options.set_access_control(
        SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlocked),
            Default::default(),
        )
        .map_err(|err| {
            crate::log::error!("==== apple failed to create access control: {:?}", err);
            SecretStoreError::backend("failed to create Apple keychain access control", err)
        })?,
    );
    let result = map_keychain_result(
        set_generic_password_options(secret, options),
        "failed to write secret to Apple protected keychain",
    );
    match &result {
        Ok(_) => crate::log::info!("==== apple store_secret_keychain_protected success"),
        Err(err) => crate::log::error!(
            "==== apple store_secret_keychain_protected failed: {:?}",
            err
        ),
    }
    result?;
    Ok(())
}
