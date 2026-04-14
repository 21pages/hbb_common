use crate::secret_store::{SecretStoreError, SecretStoreResult};
use crate::ResultType;
use osascript;
use core_foundation_sys::base::OSStatus;
use security_framework::{
    base::Error as SecurityError,
    os::macos::{
        keychain::{SecKeychain, SecPreferencesDomain},
        passwords::find_generic_password,
    },
};
use serde_derive::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

// errSecUserCanceled from Apple Security Framework (defined in SecBase.h)
// https://developer.apple.com/documentation/security/1542001-security_framework_result_codes
// https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/base/SecBase.h#L335
const ERR_SEC_USER_CANCELED: i32 = -128;

// Global flag to track if user has denied keychain access in this process
static USER_DENIED_KEYCHAIN_ACCESS: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn SecKeychainSetUserInteractionAllowed(state: u8) -> OSStatus;
    fn SecKeychainGetUserInteractionAllowed(state: *mut u8) -> OSStatus;
}

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
    load_secret_keychain_mac_generic_silent(service, account)
}

fn check_keychain_interaction_status(
    status: OSStatus,
    context: &'static str,
) -> SecretStoreResult<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(SecretStoreError::backend(
            context,
            SecurityError::from_code(status),
        ))
    }
}

fn with_keychain_interaction_disabled<T>(
    f: impl FnOnce() -> SecretStoreResult<T>,
) -> SecretStoreResult<T> {
    unsafe {
        let mut old_state: u8 = 0;
        check_keychain_interaction_status(
            SecKeychainGetUserInteractionAllowed(&mut old_state),
            "failed to query macOS keychain interaction state",
        )?;
        check_keychain_interaction_status(
            SecKeychainSetUserInteractionAllowed(0),
            "failed to disable macOS keychain interaction",
        )?;

        let result = f();
        let restore_status = SecKeychainSetUserInteractionAllowed(old_state);
        if restore_status != 0 {
            return Err(SecretStoreError::backend(
                "failed to restore macOS keychain interaction state",
                SecurityError::from_code(restore_status),
            ));
        }

        result
    }
}

pub fn load_secret_keychain_mac_generic_silent(
    service: &str,
    account: &str,
) -> SecretStoreResult<Vec<u8>> {
    // Check if user has already denied keychain access in this process
    if USER_DENIED_KEYCHAIN_ACCESS.load(Ordering::Relaxed) {
        return Err(SecretStoreError::backend_message(
            "keychain access denied by user",
            "User previously denied keychain password prompt in this session",
        ));
    }

    with_keychain_interaction_disabled(|| {
        // macOS Keychain Services refs:
        // - SecKeychainCopyDomainDefault(...)
        //   https://developer.apple.com/documentation/security/seckeychaincopydomaindefault%28_%3A_%3A%29
        // - SecKeychainFindGenericPassword(...)
        //   https://developer.apple.com/documentation/security/seckeychainfindgenericpassword%28_%3A_%3A_%3A_%3A_%3A_%3A_%3A_%3A%29
        let keychain = match crate::platform::apple::map_keychain_result(
            SecKeychain::default_for_domain(SecPreferencesDomain::User),
            "failed to open default macOS keychain",
        ) {
            Ok(k) => k,
            Err(e) => return Err(e),
        };

        let result = find_generic_password(Some(&[keychain]), service, account);

        // Check if user canceled (shouldn't happen since we disabled interaction)
        if let Err(ref err) = result {
            if err.code() == ERR_SEC_USER_CANCELED {
                USER_DENIED_KEYCHAIN_ACCESS.store(true, Ordering::Relaxed);
                return Err(SecretStoreError::backend_message(
                    "keychain access denied by user",
                    "User canceled keychain password prompt",
                ));
            }
        }

        let (secret, _) = crate::platform::apple::map_keychain_result(
            result,
            "failed to read secret from macOS login keychain",
        )?;
        Ok(secret.to_vec())
    })
}

pub fn store_secret_keychain_mac_generic(
    service: &str,
    account: &str,
    secret: &[u8],
) -> SecretStoreResult<()> {
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

    let result = keychain.set_generic_password(service, account, secret);

    // Check if user canceled the keychain password prompt
    if let Err(ref err) = result {
        if err.code() == ERR_SEC_USER_CANCELED {
            USER_DENIED_KEYCHAIN_ACCESS.store(true, Ordering::Relaxed);
            return Err(SecretStoreError::backend_message(
                "keychain access denied by user",
                "User canceled keychain password prompt",
            ));
        }
    }

    result.map_err(|err| {
        SecretStoreError::backend("failed to write secret to macOS login keychain", err)
    })?;
    Ok(())
}

pub fn store_secret_keychain_mac_generic_accessible(
    service: &str,
    account: &str,
    secret: &[u8],
) -> SecretStoreResult<()> {
    // Check if user has already denied keychain access in this process
    if USER_DENIED_KEYCHAIN_ACCESS.load(Ordering::Relaxed) {
        return Err(SecretStoreError::backend_message(
            "keychain access denied by user",
            "User previously denied keychain password prompt in this session",
        ));
    }

    // Use the `security` command-line tool to store the password with access control
    // that allows all applications to access the keychain item without prompting.
    // The `-A` flag allows all applications, and `-U` updates if the item already exists.
    use std::process::Command;

    let secret_str = String::from_utf8_lossy(secret);

    let output = Command::new("security")
        .arg("add-generic-password")
        .arg("-a")
        .arg(account)
        .arg("-s")
        .arg(service)
        .arg("-w")
        .arg(secret_str.as_ref())
        .arg("-A") // Allow all applications to access this item
        .arg("-U") // Update if item already exists
        .output()
        .map_err(|e| {
            SecretStoreError::backend_message(
                "failed to execute security command",
                &format!("Could not run security command: {}", e),
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Check if user canceled the keychain password prompt
        // errSecUserCanceled = -128, but the security command returns it as exit code 128
        if output.status.code() == Some(128) {
            USER_DENIED_KEYCHAIN_ACCESS.store(true, Ordering::Relaxed);
            return Err(SecretStoreError::backend_message(
                "keychain access denied by user",
                "User canceled keychain password prompt",
            ));
        }

        return Err(SecretStoreError::backend_message(
            "failed to write secret to macOS login keychain",
            &format!(
                "security command failed with exit code {:?}: {}",
                output.status.code(),
                stderr
            ),
        ));
    }

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
    load_secret_keychain_mac_generic_silent(service, account)
}

/// See `load_secret`: the default macOS store path deliberately stays on the
/// legacy keychain instead of the protected-data store.
pub fn store_secret(service: &str, account: &str, secret: &[u8]) -> SecretStoreResult<()> {
    store_secret_keychain_mac_generic_accessible(service, account, secret)
}
