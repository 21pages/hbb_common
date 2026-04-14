use crate::secret_store::{SecretStoreError, SecretStoreResult};
use crate::ResultType;
use osascript;
use security_framework::{
    os::macos::{
        keychain::{SecKeychain, SecPreferencesDomain},
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

    use core_foundation::{
        base::TCFType,
        boolean::CFBoolean,
        data::CFData,
        dictionary::CFDictionary,
        string::CFString,
    };
    use core_foundation_sys::base::CFTypeRef;
    use security_framework_sys::keychain_item::SecItemCopyMatching;
    use security_framework_sys::base::SecKeychainRef;

    // Declare SecKeychainGetStatus
    extern "C" {
        fn SecKeychainGetStatus(keychainRef: SecKeychainRef, keychainStatus: *mut u32) -> i32;
    }

    unsafe {
        // First check if the default keychain is locked
        let keychain = match SecKeychain::default_for_domain(SecPreferencesDomain::User) {
            Ok(k) => k,
            Err(e) => {
                return Err(SecretStoreError::backend_message(
                    "keychain access failed",
                    &format!("Failed to get default keychain: {:?}", e),
                ));
            }
        };

        let mut status_flags: u32 = 0;
        let status = SecKeychainGetStatus(keychain.as_concrete_TypeRef(), &mut status_flags);

        log::debug!("SecKeychainGetStatus returned status: {}, flags: {}", status, status_flags);

        if status != 0 {
            return Err(SecretStoreError::backend_message(
                "keychain access failed",
                &format!("Failed to get keychain status: {}", status),
            ));
        }

        // kSecUnlockStateStatus = 1
        // If bit 0 is not set, keychain is locked
        const K_SEC_UNLOCK_STATE_STATUS: u32 = 1;
        if (status_flags & K_SEC_UNLOCK_STATE_STATUS) == 0 {
            return Err(SecretStoreError::backend_message(
                "keychain is locked",
                "The keychain is locked and cannot be accessed without user interaction",
            ));
        }
        // Use the actual keychain constants
        // kSecClass = "class"
        // kSecClassGenericPassword = "genp"
        // kSecAttrService = "svce"
        // kSecAttrAccount = "acct"
        // kSecReturnData = "r_Data"
        // kSecUseAuthenticationUI = "u_AuthenticationUI"
        // kSecUseAuthenticationUIFail = "fail"

        let class_key = CFString::from_static_string("class");
        let service_key = CFString::from_static_string("svce");
        let account_key = CFString::from_static_string("acct");
        let return_data_key = CFString::from_static_string("r_Data");
        let auth_ui_key = CFString::from_static_string("u_AuthenticationUI");

        let class_value = CFString::from_static_string("genp");
        let service_value = CFString::new(service);
        let account_value = CFString::new(account);
        let return_data_value = CFBoolean::true_value();
        let auth_ui_value = CFString::from_static_string("fail");

        let query = CFDictionary::from_CFType_pairs(&[
            (class_key.as_CFType(), class_value.as_CFType()),
            (service_key.as_CFType(), service_value.as_CFType()),
            (account_key.as_CFType(), account_value.as_CFType()),
            (return_data_key.as_CFType(), return_data_value.as_CFType()),
            (auth_ui_key.as_CFType(), auth_ui_value.as_CFType()),
        ]);

        let mut result: CFTypeRef = std::ptr::null();
        let status = SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result);

        log::debug!("SecItemCopyMatching returned status: {}", status);

        if status == 0 {
            // Success
            if !result.is_null() {
                let data = CFData::wrap_under_create_rule(result as _);
                return Ok(data.bytes().to_vec());
            } else {
                return Err(SecretStoreError::backend_message(
                    "keychain read failed",
                    "SecItemCopyMatching returned null result",
                ));
            }
        }

        // Handle errors
        if status == ERR_SEC_USER_CANCELED {
            USER_DENIED_KEYCHAIN_ACCESS.store(true, Ordering::Relaxed);
            return Err(SecretStoreError::backend_message(
                "keychain access denied by user",
                "User canceled keychain password prompt",
            ));
        }

        // errSecItemNotFound = -25300
        if status == -25300 {
            return Err(SecretStoreError::backend_message(
                "secret not found",
                &format!("No keychain item found for service '{}' and account '{}'", service, account),
            ));
        }

        // errSecAuthFailed = -25293
        if status == -25293 {
            return Err(SecretStoreError::backend_message(
                "keychain access denied",
                "Application does not have permission to access this keychain item",
            ));
        }

        // errSecInteractionNotAllowed = -25308
        if status == -25308 {
            return Err(SecretStoreError::backend_message(
                "keychain interaction required",
                "Keychain access requires user interaction but it was disabled",
            ));
        }

        Err(SecretStoreError::backend_message(
            "keychain read failed",
            &format!("SecItemCopyMatching failed with error code: {}", status),
        ))
    }
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

    // Use the `security` command-line tool to store the password.
    // Without the `-A` flag, only the current application can access this item.
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
