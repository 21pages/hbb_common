use crate::secret_store::{SecretStoreError, SecretStoreResult};
use crate::ResultType;
use osascript;
use security_framework::os::macos::{
    keychain::{SecKeychain, SecPreferencesDomain},
    passwords::find_generic_password,
};
use serde_derive::{Deserialize, Serialize};

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
    let keychain = crate::platform::apple::map_keychain_result(
        SecKeychain::default_for_domain(SecPreferencesDomain::User),
        "failed to open default macOS keychain",
    )?;
    let (secret, _) = crate::platform::apple::map_keychain_result(
        find_generic_password(Some(&[keychain]), service, account),
        "failed to read secret from macOS login keychain",
    )?;
    Ok(secret.to_vec())
}

pub fn store_secret_keychain_mac_generic(
    service: &str,
    account: &str,
    secret: &[u8],
) -> SecretStoreResult<()> {
    let keychain = crate::platform::apple::map_keychain_result(
        SecKeychain::default_for_domain(SecPreferencesDomain::User),
        "failed to open default macOS keychain",
    )?;
    keychain
        .set_generic_password(service, account, secret)
        .map_err(|err| {
            SecretStoreError::backend("failed to write secret to macOS login keychain", err)
        })?;
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
