use crate::secret_store::{SecretStoreError, SecretStoreResult};
use security_framework::passwords::{generic_password, set_generic_password, PasswordOptions};

// errSecItemNotFound from Apple Security Framework (defined in SecBase.h)
// https://developer.apple.com/documentation/security/1542001-security_framework_result_codes
// https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/base/SecBase.h#L353
// Chromium similarly only special-cases `errSecItemNotFound`; other keychain
// errors are logged and returned to the caller unchanged:
// https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/common/keychain_password_mac.mm#97
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
    // Chromium refs for the same Apple Keychain generic-password read path:
    // - components/os_crypt/common/keychain_password_mac.mm
    //   https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/common/keychain_password_mac.mm#90
    // - crypto/apple_keychain_v2.mm
    //   https://chromium.googlesource.com/chromium/src/crypto/%2B/10f9ffa5665e43c06789d79107ffa55dd90941f6/apple_keychain_v2.mm#74
    // - crypto/apple_keychain_secitem.mm
    //   https://chromium.googlesource.com/chromium/src/crypto/%2B/a9fb8248f71fb032d1dd53e7b3682c847d88024d/apple_keychain_secitem.mm#101
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
    // Apple Security.framework refs used by `security-framework::passwords::set_generic_password`:
    // - SecItemAdd(...)
    //   https://developer.apple.com/documentation/security/secitemadd%28_%3A_%3A%29
    // - SecItemUpdate(...)
    //   https://developer.apple.com/documentation/security/secitemupdate%28_%3A_%3A%29
    // Chromium refs for the same Apple Keychain generic-password write path:
    // - AddRandomPasswordToKeychain
    //   https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/common/keychain_password_mac.mm#69
    // - AddGenericPassword
    //   https://chromium.googlesource.com/chromium/src/crypto/%2B/a9fb8248f71fb032d1dd53e7b3682c847d88024d/apple_keychain_secitem.mm#94
    map_keychain_result(
        set_generic_password(service, account, secret),
        "failed to write secret to Apple generic keychain",
    )?;
    Ok(())
}
