use crate::secret_store::{SecretStoreError, SecretStoreResult};
use crate::ResultType;
use osascript;
use security_framework::os::macos::{
    keychain::{SecKeychain, SecPreferencesDomain},
    passwords::find_generic_password,
};
use serde_derive::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

// errSecUserCanceled from Apple Security Framework (defined in SecBase.h)
// https://developer.apple.com/documentation/security/1542001-security_framework_result_codes
// https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/base/SecBase.h#L335
const ERR_SEC_USER_CANCELED: i32 = -128;

// Global flag to track if user has denied keychain access in this process
static USER_DENIED_KEYCHAIN_ACCESS: AtomicBool = AtomicBool::new(false);

#[derive(Serialize)]
struct AlertParams {
    title: String,
    message: String,
    alert_type: String,
    buttons: Vec<String>,
}

#[derive(Deserialize)]
struct AlertResult {
    #[serde(rename = "buttonReturned")]
    button: String,
}

/// Firstly run the specified app, then alert a dialog. Return the clicked button value.
///
/// # Arguments
///
/// * `app` - The app to execute the script.
/// * `alert_type` - Alert type. . informational, warning, critical
/// * `title` - The alert title.
/// * `message` - The alert message.
/// * `buttons` - The buttons to show.
pub fn alert(
    app: String,
    alert_type: String,
    title: String,
    message: String,
    buttons: Vec<String>,
) -> ResultType<String> {
    let script = osascript::JavaScript::new(&format!(
        "
    var App = Application('{}');
    App.includeStandardAdditions = true;
    return App.displayAlert($params.title, {{
        message: $params.message,
        'as': $params.alert_type,
        buttons: $params.buttons,
    }});
    ",
        app
    ));

    let result: AlertResult = script.execute_with_params(AlertParams {
        title,
        message,
        alert_type,
        buttons,
    })?;
    Ok(result.button)
}

pub fn load_secret_keychain_mac_generic(
    service: &str,
    account: &str,
) -> SecretStoreResult<Vec<u8>> {
    crate::log::info!(
        "==== macos load_secret_keychain_mac_generic service={} account={}",
        service,
        account
    );
    // Check if user has already denied keychain access in this process
    if USER_DENIED_KEYCHAIN_ACCESS.load(Ordering::Relaxed) {
        return Err(SecretStoreError::backend_message(
            "keychain access denied by user",
            "User previously denied keychain password prompt in this session",
        ));
    }

    // macOS Keychain Services refs:
    // - SecKeychainCopyDomainDefault(...)
    //   https://developer.apple.com/documentation/security/seckeychaincopydomaindefault%28_%3A_%3A%29
    // - SecKeychainFindGenericPassword(...)
    //   https://developer.apple.com/documentation/security/seckeychainfindgenericpassword%28_%3A_%3A_%3A_%3A_%3A_%3A_%3A_%3A%29
    let keychain = crate::platform::apple::map_keychain_result(
        SecKeychain::default_for_domain(SecPreferencesDomain::User),
        "failed to open default macOS keychain",
    )?;
    crate::log::info!("==== macos opened default keychain");

    let result = find_generic_password(Some(&[keychain]), service, account);

    // Check if user canceled the keychain password prompt
    if let Err(ref err) = result {
        if err.code() == ERR_SEC_USER_CANCELED {
            crate::log::error!("==== macos user canceled keychain read prompt");
            USER_DENIED_KEYCHAIN_ACCESS.store(true, Ordering::Relaxed);
            return Err(SecretStoreError::backend_message(
                "keychain access denied by user",
                "User canceled keychain password prompt",
            ));
        }
    }

    let result = crate::platform::apple::map_keychain_result(
        result,
        "failed to read secret from macOS login keychain",
    );
    match &result {
        Ok((secret, _)) => crate::log::info!(
            "==== macos load_secret_keychain_mac_generic success, secret_len={} secret_hex={}",
            secret.len(),
            crate::platform::bytes_to_hex(secret)
        ),
        Err(err) => crate::log::error!(
            "==== macos load_secret_keychain_mac_generic failed: {:?}",
            err
        ),
    }
    let (secret, _) = result?;
    Ok(secret.to_vec())
}

pub fn store_secret_keychain_mac_generic(
    service: &str,
    account: &str,
    secret: &[u8],
) -> SecretStoreResult<()> {
    crate::log::info!(
        "==== macos store_secret_keychain_mac_generic service={} account={} secret_len={} secret_hex={}",
        service,
        account,
        secret.len(),
        crate::platform::bytes_to_hex(secret)
    );
    // Check if user has already denied keychain access in this process
    if USER_DENIED_KEYCHAIN_ACCESS.load(Ordering::Relaxed) {
        return Err(SecretStoreError::backend_message(
            "keychain access denied by user",
            "User previously denied keychain password prompt in this session",
        ));
    }

    // macOS Keychain Services refs:
    // - SecKeychainCopyDomainDefault(...)
    //   https://developer.apple.com/documentation/security/seckeychaincopydomaindefault%28_%3A_%3A%29
    // - SecKeychainAddGenericPassword(...)
    //   https://developer.apple.com/documentation/security/seckeychainaddgenericpassword%28_%3A_%3A_%3A_%3A_%3A_%3A_%3A_%3A%29
    // - SecKeychainItemModifyAttributesAndData(...)
    //   https://developer.apple.com/documentation/security/seckeychainitemmodifyattributesanddata%28_%3A_%3A_%3A_%3A%29
    let keychain = crate::platform::apple::map_keychain_result(
        SecKeychain::default_for_domain(SecPreferencesDomain::User),
        "failed to open default macOS keychain",
    )?;
    crate::log::info!("==== macos opened default keychain");

    let result = keychain.set_generic_password(service, account, secret);

    // Check if user canceled the keychain password prompt
    if let Err(ref err) = result {
        if err.code() == ERR_SEC_USER_CANCELED {
            crate::log::error!("==== macos user canceled keychain write prompt");
            USER_DENIED_KEYCHAIN_ACCESS.store(true, Ordering::Relaxed);
            return Err(SecretStoreError::backend_message(
                "keychain access denied by user",
                "User canceled keychain password prompt",
            ));
        }
    }

    result.map_err(|err| {
        crate::log::error!("==== macos failed to set generic password: {:?}", err);
        SecretStoreError::backend("failed to write secret to macOS login keychain", err)
    })?;
    crate::log::info!("==== macos store_secret_keychain_mac_generic success");
    Ok(())
}

/// RustDesk's default macOS path intentionally uses the traditional keychain.
///
/// The `apple::load_secret_keychain_protected` helper targets macOS's Data
/// Protection Keychain, which is closer to the iOS model and can reject normal
/// desktop / CLI execution contexts even when the `(service, account)` values
/// are valid. For the desktop app we want the broadly compatible login
/// keychain-backed behavior here.
pub fn load_secret(service: &str, account: &str) -> SecretStoreResult<Vec<u8>> {
    load_secret_keychain_mac_generic(service, account)
}

/// See `load_secret`: the default macOS store path deliberately stays on the
/// legacy keychain instead of the protected-data store.
pub fn store_secret(service: &str, account: &str, secret: &[u8]) -> SecretStoreResult<()> {
    store_secret_keychain_mac_generic(service, account, secret)
}
