use crate::secret_store::{SecretStoreError, SecretStoreResult};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    passwords::{
        generic_password, set_generic_password, set_generic_password_options, PasswordOptions,
    },
};

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
    map_keychain_result(
        generic_password(PasswordOptions::new_generic_password(service, account)),
        "failed to read secret from Apple generic keychain",
    )
}

pub fn store_secret_keychain_generic(
    service: &str,
    account: &str,
    secret: &[u8],
) -> SecretStoreResult<()> {
    map_keychain_result(
        set_generic_password(service, account, secret),
        "failed to write secret to Apple generic keychain",
    )?;
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
    let mut options = PasswordOptions::new_generic_password(service, account);
    options.use_protected_keychain();
    map_keychain_result(
        generic_password(options),
        "failed to read secret from Apple protected keychain",
    )
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
    let mut options = PasswordOptions::new_generic_password(service, account);
    options.use_protected_keychain();
    options.set_access_control(
        SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlocked),
            Default::default(),
        )
        .map_err(|err| {
            SecretStoreError::backend("failed to create Apple keychain access control", err)
        })?,
    );
    map_keychain_result(
        set_generic_password_options(secret, options),
        "failed to write secret to Apple protected keychain",
    )?;
    Ok(())
}
