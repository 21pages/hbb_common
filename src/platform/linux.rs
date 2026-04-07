use crate::secret_store::{SecretStoreError, SecretStoreResult};
use crate::ResultType;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use dbus::{
    arg::{
        OwnedFd as DbusOwnedFd, PropMap as DbusPropMap, ReadAll as DbusReadAll,
        TypeMismatchError as DbusTypeMismatchError,
    },
    blocking::Connection as DbusConnection,
    message::SignalArgs as DbusSignalArgs,
    strings::{BusName as DbusBusName, Path as DbusPath},
    Message as DbusMessage,
};
use dbus_secret_service::{EncryptionType, Item, SecretService};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::{fs::OpenOptionsExt, io::AsRawFd},
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc::{channel, Receiver, Sender, TryRecvError},
    time::Duration,
};
use users::{get_current_uid, get_user_by_uid, os::unix::UserExt};

use sctk::{
    output::OutputData,
    output::{OutputHandler, OutputState},
    reexports::client::protocol::wl_output::WlOutput,
    reexports::client::{globals, Proxy},
    reexports::client::{Connection, QueueHandle},
    registry::{ProvidesRegistryState, RegistryState},
};

lazy_static::lazy_static! {
    pub static ref DISTRO: Distro = Distro::new();
}

// to-do: There seems to be some runtime issue that causes the audit logs to be generated.
// We may need to fix this and remove this workaround in the future.
//
// We use the pre-search method to find the command path to avoid the audit logs on some systems.
// No idea why the audit logs happen.
// Though the audit logs may disappear after rebooting.
//
// See https://github.com/rustdesk/rustdesk/discussions/11959
//
// `ausearch -x /usr/share/rustdesk/rustdesk` will return
// ...
// time->Tue Jun 24 10:40:43 2025
// type=PROCTITLE msg=audit(1750776043.446:192757): proctitle=2F7573722F62696E2F727573746465736B002D2D73657276696365
// type=PATH msg=audit(1750776043.446:192757): item=0 name="/usr/local/bin/sh" nametype=UNKNOWN cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
// type=CWD msg=audit(1750776043.446:192757): cwd="/"
// type=SYSCALL msg=audit(1750776043.446:192757): arch=c000003e syscall=59 success=no exit=-2 a0=7fb7dbd22da0 a1=1d65f2c0 a2=7ffc25193360 a3=7ffc25194ec0 items=1 ppid=172208 pid=267565 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="rustdesk" exe="/usr/share/rustdesk/rustdesk" subj=unconfined key="processos_criados"
// ----
// time->Tue Jun 24 10:40:43 2025
// type=PROCTITLE msg=audit(1750776043.446:192758): proctitle=2F7573722F62696E2F727573746465736B002D2D73657276696365
// type=PATH msg=audit(1750776043.446:192758): item=0 name="/usr/sbin/sh" nametype=UNKNOWN cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
// ...
lazy_static::lazy_static! {
    pub static ref CMD_LOGINCTL: String = find_cmd_path("loginctl");
    pub static ref CMD_PS: String = find_cmd_path("ps");
    pub static ref CMD_SH: String = find_cmd_path("sh");
}

pub const DISPLAY_SERVER_WAYLAND: &str = "wayland";
pub const DISPLAY_SERVER_X11: &str = "x11";
pub const DISPLAY_DESKTOP_KDE: &str = "KDE";

const DESKTOP_SESSION: &str = "DESKTOP_SESSION";
const GNOME_DESKTOP_SESSION_ID: &str = "GNOME_DESKTOP_SESSION_ID";
const KDE_FULL_SESSION: &str = "KDE_FULL_SESSION";
pub const XDG_CURRENT_DESKTOP: &str = "XDG_CURRENT_DESKTOP";

pub struct Distro {
    pub name: String,
    pub version_id: String,
}

impl Distro {
    fn new() -> Self {
        let name = run_cmds("awk -F'=' '/^NAME=/ {print $2}' /etc/os-release")
            .unwrap_or_default()
            .trim()
            .trim_matches('"')
            .to_string();
        let version_id = run_cmds("awk -F'=' '/^VERSION_ID=/ {print $2}' /etc/os-release")
            .unwrap_or_default()
            .trim()
            .trim_matches('"')
            .to_string();
        Self { name, version_id }
    }
}

fn find_cmd_path(cmd: &'static str) -> String {
    let test_cmd = format!("/bin/{}", cmd);
    if std::path::Path::new(&test_cmd).exists() {
        return test_cmd;
    }
    let test_cmd = format!("/usr/bin/{}", cmd);
    if std::path::Path::new(&test_cmd).exists() {
        return test_cmd;
    }
    if let Ok(output) = Command::new("which").arg(cmd).output() {
        if output.status.success() {
            return String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }
    cmd.to_string()
}

// Deprecated. Use `hbb_common::platform::linux::is_kde_session()` instead for now.
// Or we need to set the correct environment variable in the server process.
#[inline]
pub fn is_kde() -> bool {
    if let Ok(env) = std::env::var(XDG_CURRENT_DESKTOP) {
        env == DISPLAY_DESKTOP_KDE
    } else {
        false
    }
}

// Don't use `hbb_common::platform::linux::is_kde()` here.
// It's not correct in the server process.
pub fn is_kde_session() -> bool {
    std::process::Command::new(CMD_SH.as_str())
        .arg("-c")
        .arg("pgrep -f kded[0-9]+")
        .stdout(std::process::Stdio::piped())
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

#[inline]
pub fn is_gdm_user(username: &str) -> bool {
    username == "gdm" || username == "sddm"
    // || username == "lightgdm"
}

#[inline]
pub fn is_desktop_wayland() -> bool {
    get_display_server() == DISPLAY_SERVER_WAYLAND
}

#[inline]
pub fn is_x11_or_headless() -> bool {
    !is_desktop_wayland()
}

// -1
const INVALID_SESSION: &str = "4294967295";

pub fn get_display_server() -> String {
    // Check for forced display server environment variable first
    if let Ok(forced_display) = std::env::var("RUSTDESK_FORCED_DISPLAY_SERVER") {
        return forced_display;
    }

    // Check if `loginctl` can be called successfully
    if run_loginctl(None).is_err() {
        return DISPLAY_SERVER_X11.to_owned();
    }

    let mut session = get_values_of_seat0(&[0])[0].clone();
    if session.is_empty() {
        // loginctl has not given the expected output.  try something else.
        if let Ok(sid) = std::env::var("XDG_SESSION_ID") {
            // could also execute "cat /proc/self/sessionid"
            session = sid;
        }
        if session.is_empty() {
            session = run_cmds("cat /proc/self/sessionid").unwrap_or_default();
            if session == INVALID_SESSION {
                session = "".to_owned();
            }
        }
    }
    if session.is_empty() {
        std::env::var("XDG_SESSION_TYPE").unwrap_or("x11".to_owned())
    } else {
        get_display_server_of_session(&session)
    }
}

pub fn get_display_server_of_session(session: &str) -> String {
    let mut display_server = if let Ok(output) =
        run_loginctl(Some(vec!["show-session", "-p", "Type", session]))
    // Check session type of the session
    {
        String::from_utf8_lossy(&output.stdout)
            .replace("Type=", "")
            .trim_end()
            .into()
    } else {
        "".to_owned()
    };
    if display_server.is_empty() || display_server == "tty" || display_server == "unspecified" {
        if let Ok(sestype) = std::env::var("XDG_SESSION_TYPE") {
            if !sestype.is_empty() {
                return sestype.to_lowercase();
            }
        }
        display_server = "x11".to_owned();
    }
    display_server.to_lowercase()
}

#[inline]
fn line_values(indices: &[usize], line: &str) -> Vec<String> {
    indices
        .into_iter()
        .map(|idx| line.split_whitespace().nth(*idx).unwrap_or("").to_owned())
        .collect::<Vec<String>>()
}

#[inline]
pub fn get_values_of_seat0(indices: &[usize]) -> Vec<String> {
    _get_values_of_seat0(indices, true)
}

#[inline]
pub fn get_values_of_seat0_with_gdm_wayland(indices: &[usize]) -> Vec<String> {
    _get_values_of_seat0(indices, false)
}

// Ignore "3 sessions listed."
fn ignore_loginctl_line(line: &str) -> bool {
    line.contains("sessions") || line.split(" ").count() < 4
}

fn _get_values_of_seat0(indices: &[usize], ignore_gdm_wayland: bool) -> Vec<String> {
    if let Ok(output) = run_loginctl(None) {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if ignore_loginctl_line(line) {
                continue;
            }
            if line.contains("seat0") {
                if let Some(sid) = line.split_whitespace().next() {
                    if is_active(sid) {
                        if ignore_gdm_wayland {
                            if is_gdm_user(line.split_whitespace().nth(2).unwrap_or(""))
                                && get_display_server_of_session(sid) == DISPLAY_SERVER_WAYLAND
                            {
                                continue;
                            }
                        }
                        return line_values(indices, line);
                    }
                }
            }
        }

        // some case, there is no seat0 https://github.com/rustdesk/rustdesk/issues/73
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if ignore_loginctl_line(line) {
                continue;
            }
            if let Some(sid) = line.split_whitespace().next() {
                if is_active(sid) {
                    let d = get_display_server_of_session(sid);
                    if ignore_gdm_wayland {
                        if is_gdm_user(line.split_whitespace().nth(2).unwrap_or(""))
                            && d == DISPLAY_SERVER_WAYLAND
                        {
                            continue;
                        }
                    }
                    if d == "tty" || d == "unspecified" {
                        continue;
                    }
                    return line_values(indices, line);
                }
            }
        }
    }

    line_values(indices, "")
}

pub fn is_active(sid: &str) -> bool {
    if let Ok(output) = run_loginctl(Some(vec!["show-session", "-p", "State", sid])) {
        String::from_utf8_lossy(&output.stdout).contains("active")
    } else {
        false
    }
}

pub fn is_active_and_seat0(sid: &str) -> bool {
    if let Ok(output) = run_loginctl(Some(vec!["show-session", sid])) {
        String::from_utf8_lossy(&output.stdout).contains("State=active")
            && String::from_utf8_lossy(&output.stdout).contains("Seat=seat0")
    } else {
        false
    }
}

// Check both "Lock" and "Switch user"
pub fn is_session_locked(sid: &str) -> bool {
    if let Ok(output) = run_loginctl(Some(vec!["show-session", sid, "--property=LockedHint"])) {
        String::from_utf8_lossy(&output.stdout).contains("LockedHint=yes")
    } else {
        false
    }
}

// **Note** that the return value here, the last character is '\n'.
// Use `run_cmds_trim_newline()` if you want to remove '\n' at the end.
pub fn run_cmds(cmds: &str) -> ResultType<String> {
    let output = std::process::Command::new(CMD_SH.as_str())
        .args(vec!["-c", cmds])
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn run_cmds_trim_newline(cmds: &str) -> ResultType<String> {
    let output = std::process::Command::new(CMD_SH.as_str())
        .args(vec!["-c", cmds])
        .output()?;
    let out = String::from_utf8_lossy(&output.stdout);
    Ok(if out.ends_with('\n') {
        out[..out.len() - 1].to_string()
    } else {
        out.to_string()
    })
}

fn run_loginctl(args: Option<Vec<&str>>) -> std::io::Result<std::process::Output> {
    if std::env::var("FLATPAK_ID").is_ok() {
        let mut l_args = CMD_LOGINCTL.to_string();
        if let Some(a) = args.as_ref() {
            l_args = format!("{} {}", l_args, a.join(" "));
        }
        let res = std::process::Command::new("flatpak-spawn")
            .args(vec![String::from("--host"), l_args])
            .output();
        if res.is_ok() {
            return res;
        }
    }
    let mut cmd = std::process::Command::new(CMD_LOGINCTL.as_str());
    if let Some(a) = args {
        return cmd.args(a).output();
    }
    cmd.output()
}

/// forever: may not work
#[cfg(target_os = "linux")]
pub fn system_message(title: &str, msg: &str, forever: bool) -> ResultType<()> {
    let cmds: HashMap<&str, Vec<&str>> = HashMap::from([
        ("notify-send", [title, msg].to_vec()),
        (
            "zenity",
            [
                "--info",
                "--timeout",
                if forever { "0" } else { "3" },
                "--title",
                title,
                "--text",
                msg,
            ]
            .to_vec(),
        ),
        ("kdialog", ["--title", title, "--msgbox", msg].to_vec()),
        (
            "xmessage",
            [
                "-center",
                "-timeout",
                if forever { "0" } else { "3" },
                title,
                msg,
            ]
            .to_vec(),
        ),
    ]);
    for (k, v) in cmds {
        if Command::new(k).args(v).spawn().is_ok() {
            return Ok(());
        }
    }
    crate::bail!("failed to post system message");
}

#[derive(Debug, Clone)]
pub struct WaylandDisplayInfo {
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub logical_size: Option<(i32, i32)>,
    pub refresh_rate: i32,
}

// Retrieves information about all connected displays via the Wayland protocol.
pub fn get_wayland_displays() -> ResultType<Vec<WaylandDisplayInfo>> {
    struct WaylandEnv {
        registry_state: RegistryState,
        output_state: OutputState,
    }

    impl OutputHandler for WaylandEnv {
        fn output_state(&mut self) -> &mut OutputState {
            &mut self.output_state
        }

        fn new_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: WlOutput) {}
        fn update_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: WlOutput) {}
        fn output_destroyed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: WlOutput) {}
    }

    impl ProvidesRegistryState for WaylandEnv {
        fn registry(&mut self) -> &mut RegistryState {
            &mut self.registry_state
        }

        sctk::registry_handlers!();
    }

    sctk::delegate_output!(WaylandEnv);
    sctk::delegate_registry!(WaylandEnv);

    let conn = Connection::connect_to_env()?;
    let (globals, mut event_queue) = globals::registry_queue_init(&conn)?;
    let queue_handle = event_queue.handle();

    let registry_state = RegistryState::new(&globals);
    let output_state = OutputState::new(&globals, &queue_handle);

    let mut environment = WaylandEnv {
        registry_state,
        output_state,
    };

    event_queue.roundtrip(&mut environment)?;

    let outputs: Vec<_> = environment.output_state.outputs().collect();
    let mut display_infos = Vec::new();

    for output in outputs {
        if let Some(output_data) = output.data::<OutputData>() {
            output_data.with_output_info(|info| {
                if let Some(mode) = info.modes.iter().find(|m| m.current) {
                    let (x, y) = info.location;
                    let (width, height) = mode.dimensions;
                    let refresh_rate = mode.refresh_rate;
                    let name = info.name.clone().unwrap_or_default();
                    let logical_size = info.logical_size;
                    display_infos.push(WaylandDisplayInfo {
                        name,
                        x,
                        y,
                        width,
                        height,
                        logical_size,
                        refresh_rate,
                    });
                }
            });
        }
    }

    Ok(display_infos)
}

/// Escape a string for safe use in shell commands by wrapping in single quotes.
///
/// This function handles the edge case of single quotes within the string by:
/// 1. Ending the current single-quoted section
/// 2. Adding an escaped single quote
/// 3. Starting a new single-quoted section
///
/// Example: "it's here" -> "'it'\''s here'"
#[inline]
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace("'", "'\\''"))
}

/// Get the current user's home directory via getpwuid (trusted source).
///
/// This function uses the system's password database (via `getpwuid`) to retrieve
/// the home directory, avoiding the security risk of relying on the `HOME`
/// environment variable which can be manipulated by untrusted input.
///
/// # Returns
/// - `Some(PathBuf)` if the home directory was found and exists
/// - `None` if the user lookup failed or the directory doesn't exist
///
/// # Security
/// This function is designed to be safe against confused-deputy attacks where
/// an attacker might manipulate environment variables to influence privileged
/// operations.
pub fn get_home_dir_trusted() -> Option<PathBuf> {
    let uid = get_current_uid();
    match get_user_by_uid(uid) {
        Some(user) => {
            let home = user.home_dir();
            if Path::is_dir(home) {
                Some(PathBuf::from(home))
            } else {
                log::warn!(
                    "Home directory for uid {} does not exist or is not a directory: {:?}",
                    uid,
                    home
                );
                None
            }
        }
        None => {
            log::warn!("Failed to get user info for uid {}", uid);
            None
        }
    }
}

const FLATPAK_PORTAL_DEST: &str = "org.freedesktop.portal.Desktop";
const FLATPAK_PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const FLATPAK_PORTAL_SECRET_INTERFACE: &str = "org.freedesktop.portal.Secret";
const FLATPAK_PORTAL_METHOD_TIMEOUT_MS: u64 = 10_000;
const FLATPAK_PORTAL_REQUEST_TIMEOUT_SECS: u64 = 15;
const FLATPAK_SECRET_DERIVE_INFO: &[u8] = b"hbb-common-flatpak-secret-v1";
// Chromium refs:
// - components/os_crypt/sync/kwallet_dbus.cc:18-31
// - https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/sync/kwallet_dbus.cc#18
const KWALLET_INTERFACE: &str = "org.kde.KWallet";
const KWALLET_KLAUNCHER_SERVICE: &str = "org.kde.klauncher";
const KWALLET_KLAUNCHER_PATH: &str = "/KLauncher";
const KWALLET_KLAUNCHER_INTERFACE: &str = "org.kde.KLauncher";
const KWALLET_TIMEOUT_MS: u64 = 10_000;
const KWALLET_INVALID_HANDLE: i32 = -1;
// Follow Chromium's password-entry KWallet path instead of KWallet's binary
// stream-entry APIs:
// - components/os_crypt/sync/key_storage_kwallet.cc:113-137
// - https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/sync/key_storage_kwallet.cc#113
const KWALLET_ENTRY_TYPE_PASSWORD: i32 = 1;
const KDE_SESSION_VERSION: &str = "KDE_SESSION_VERSION";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinuxSecretBackend {
    SecretService,
    KWallet(KWalletService),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DesktopEnvironment {
    Other,
    Kde3,
    Kde4,
    Kde5,
    Kde6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KWalletService {
    Legacy,
    KWallet5,
    KWallet6,
}

impl KWalletService {
    fn service_name(self) -> &'static str {
        match self {
            Self::Legacy => "org.kde.kwalletd",
            Self::KWallet5 => "org.kde.kwalletd5",
            Self::KWallet6 => "org.kde.kwalletd6",
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::Legacy => "/modules/kwalletd",
            Self::KWallet5 => "/modules/kwalletd5",
            Self::KWallet6 => "/modules/kwalletd6",
        }
    }

    fn daemon_name(self) -> &'static str {
        match self {
            Self::Legacy => "kwalletd",
            Self::KWallet5 => "kwalletd5",
            Self::KWallet6 => "kwalletd6",
        }
    }
}

#[derive(Debug)]
struct PortalRequestResponse {
    path: Option<DbusPath<'static>>,
    response: u32,
    results: DbusPropMap,
}

#[derive(Debug)]
struct PortalRequestResponseBody {
    response: u32,
    results: DbusPropMap,
}

impl DbusReadAll for PortalRequestResponseBody {
    fn read(i: &mut dbus::arg::Iter) -> Result<Self, DbusTypeMismatchError> {
        Ok(Self {
            response: i.read()?,
            results: i.read()?,
        })
    }
}

impl DbusSignalArgs for PortalRequestResponseBody {
    const NAME: &'static str = "Response";
    const INTERFACE: &'static str = "org.freedesktop.portal.Request";
}

#[inline]
fn is_flatpak() -> bool {
    PathBuf::from("/.flatpak-info").exists()
}

fn retrieve_flatpak_portal_secret() -> SecretStoreResult<Vec<u8>> {
    // Flatpak/XDG portal refs:
    // - org.freedesktop.portal.Secret.RetrieveSecret
    //   https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html
    // - org.freedesktop.portal.Request::Response
    //   https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Request.html
    let conn = DbusConnection::new_session().map_err(|err| {
        SecretStoreError::backend("failed to connect to xdg-desktop-portal session bus", err)
    })?;

    let sender: DbusBusName<'static> = FLATPAK_PORTAL_DEST.into();
    let rule = PortalRequestResponseBody::match_rule(Some(&sender), None).static_clone();
    let (tx, rx): (
        Sender<PortalRequestResponse>,
        Receiver<PortalRequestResponse>,
    ) = channel();
    let match_token = conn
        .add_match(
            rule,
            move |signal: PortalRequestResponseBody, _: &DbusConnection, message: &DbusMessage| {
                let _ = tx.send(PortalRequestResponse {
                    path: message.path().map(DbusPath::into_static),
                    response: signal.response,
                    results: signal.results,
                });
                false
            },
        )
        .map_err(|err| {
            SecretStoreError::backend(
                "failed to subscribe to xdg-desktop-portal secret response",
                err,
            )
        })?;

    let mut secret_file = open_unlinked_temp_secret_file()?;
    let portal_fd = dup_dbus_fd(secret_file.as_raw_fd())?;
    let portal_proxy = conn.with_proxy(
        FLATPAK_PORTAL_DEST,
        FLATPAK_PORTAL_PATH,
        Duration::from_millis(FLATPAK_PORTAL_METHOD_TIMEOUT_MS),
    );
    let (request_path,) =
        match portal_proxy.method_call(FLATPAK_PORTAL_SECRET_INTERFACE, "RetrieveSecret", (portal_fd, DbusPropMap::new())) {
            Ok(path) => path,
            Err(err) => {
                let _ = conn.remove_match(match_token);
                return Err(SecretStoreError::backend(
                    "failed to request xdg-desktop-portal secret",
                    err,
                ));
            }
        };

    let response = wait_for_flatpak_portal_response(&conn, &rx, &request_path);
    let _ = conn.remove_match(match_token);
    let response = response?;
    if response.response != 0 {
        let detail = if response.results.is_empty() {
            format!("request failed with response code {}", response.response)
        } else {
            format!(
                "request failed with response code {} and {} result fields",
                response.response,
                response.results.len()
            )
        };
        return Err(SecretStoreError::backend_message(
            "failed to retrieve xdg-desktop-portal secret",
            detail,
        ));
    }

    secret_file.seek(SeekFrom::Start(0)).map_err(|err| {
        SecretStoreError::backend("failed to rewind xdg-desktop-portal secret buffer", err)
    })?;
    let mut secret = Vec::new();
    secret_file.read_to_end(&mut secret).map_err(|err| {
        SecretStoreError::backend("failed to read xdg-desktop-portal secret buffer", err)
    })?;
    if secret.is_empty() {
        return Err(SecretStoreError::backend_message(
            "failed to retrieve xdg-desktop-portal secret",
            "portal returned an empty secret buffer",
        ));
    }
    Ok(secret)
}

fn wait_for_flatpak_portal_response(
    conn: &DbusConnection,
    rx: &Receiver<PortalRequestResponse>,
    expected_path: &DbusPath<'static>,
) -> SecretStoreResult<PortalRequestResponse> {
    let one_second = Duration::from_millis(1000);
    for _ in 0..FLATPAK_PORTAL_REQUEST_TIMEOUT_SECS {
        match take_matching_flatpak_portal_response(rx, expected_path)? {
            Some(signal) => return Ok(signal),
            None => {}
        }
        match conn.process(one_second) {
            Ok(false) => continue,
            Ok(true) => match take_matching_flatpak_portal_response(rx, expected_path)? {
                Some(signal) => return Ok(signal),
                None => continue,
            },
            Err(err) => {
                return Err(SecretStoreError::backend(
                    "failed while waiting for xdg-desktop-portal secret response",
                    err,
                ));
            }
        }
    }
    Err(SecretStoreError::backend_message(
        "timed out waiting for xdg-desktop-portal secret response",
        format!(
            "portal request exceeded {} seconds",
            FLATPAK_PORTAL_REQUEST_TIMEOUT_SECS
        ),
    ))
}

fn take_matching_flatpak_portal_response(
    rx: &Receiver<PortalRequestResponse>,
    expected_path: &DbusPath<'static>,
) -> SecretStoreResult<Option<PortalRequestResponse>> {
    loop {
        match rx.try_recv() {
            Ok(signal) => {
                let Some(path) = signal.path.as_ref() else {
                    return Err(SecretStoreError::backend_message(
                        "failed to retrieve xdg-desktop-portal secret",
                        "portal response did not include a request path",
                    ));
                };
                if path == expected_path {
                    return Ok(Some(signal));
                }
                log::warn!(
                    "Ignoring xdg-desktop-portal secret response for unexpected request path: expected {}, got {}",
                    expected_path,
                    path
                );
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => return Ok(None),
        }
        return Ok(None);
    }
}

fn open_unlinked_temp_secret_file() -> SecretStoreResult<File> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        ".hbb-flatpak-secret-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|err| {
            SecretStoreError::backend("failed to create xdg-desktop-portal secret buffer", err)
        })?;
    fs::remove_file(&path).map_err(|err| {
        SecretStoreError::backend("failed to unlink xdg-desktop-portal secret buffer", err)
    })?;
    Ok(file)
}

fn dup_dbus_fd(fd: i32) -> SecretStoreResult<DbusOwnedFd> {
    // POSIX ref: dup(2)
    // https://man7.org/linux/man-pages/man2/dup2.2.html
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err(SecretStoreError::backend(
            "failed to duplicate xdg-desktop-portal secret file descriptor",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { DbusOwnedFd::new(dup_fd) })
}

// The Secret portal exposes a stable per-app secret but does not provide an
// item store like Secret Service. For Flatpak, derive a stable 32-byte secret
// per service/account from that app secret instead of persisting extra data.
fn derive_flatpak_secret(service: &str, account: &str, portal_secret: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(FLATPAK_SECRET_DERIVE_INFO);
    hasher.update(b"\0");
    hasher.update(service.as_bytes());
    hasher.update(b"\0");
    hasher.update(account.as_bytes());
    hasher.update(b"\0");
    hasher.update(portal_secret);
    hasher.finalize().to_vec()
}

fn load_flatpak_secret_store_key(service: &str, account: &str) -> SecretStoreResult<Vec<u8>> {
    let portal_secret = retrieve_flatpak_portal_secret()?;
    Ok(derive_flatpak_secret(service, account, &portal_secret))
}

fn store_flatpak_secret_store_key(
    service: &str,
    account: &str,
    secret: &[u8],
) -> SecretStoreResult<()> {
    let expected = load_flatpak_secret_store_key(service, account)?;
    if secret == expected.as_slice() {
        Ok(())
    } else {
        Err(SecretStoreError::backend_message(
            "Flatpak secret backend is read-only",
            "requested secret does not match the portal-derived secret",
        ))
    }
}

fn linux_secret_backend() -> LinuxSecretBackend {
    // Chromium refs:
    // - components/os_crypt/sync/key_storage_util_linux.cc:44-68
    // - base/nix/xdg_util.cc:83-174
    // - https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/sync/key_storage_util_linux.cc#44
    // - https://chromium.googlesource.com/chromium/src/+/main/base/nix/xdg_util.cc#83
    //
    // Match Chromium's backend selection by resolving the desktop environment
    // from XDG_CURRENT_DESKTOP / DESKTOP_SESSION / KDE_* environment variables,
    // then using KWallet only for KDE4/5/6.
    match detect_desktop_environment() {
        DesktopEnvironment::Kde4 | DesktopEnvironment::Kde5 | DesktopEnvironment::Kde6 => {
            LinuxSecretBackend::KWallet(detect_kwallet_service())
        }
        DesktopEnvironment::Other | DesktopEnvironment::Kde3 => {
            LinuxSecretBackend::SecretService
        }
    }
}

fn detect_kwallet_service() -> KWalletService {
    // Chromium refs:
    // - base/nix/xdg_util.cc:110-119,146-172
    // - components/os_crypt/sync/kwallet_dbus.cc:35-47
    // - https://chromium.googlesource.com/chromium/src/+/main/base/nix/xdg_util.cc#110
    // - https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/sync/kwallet_dbus.cc#35
    match detect_desktop_environment() {
        DesktopEnvironment::Kde6 => KWalletService::KWallet6,
        DesktopEnvironment::Kde5 => KWalletService::KWallet5,
        DesktopEnvironment::Other | DesktopEnvironment::Kde3 | DesktopEnvironment::Kde4 => {
            KWalletService::Legacy
        }
    }
}

fn detect_desktop_environment() -> DesktopEnvironment {
    if let Ok(xdg_current_desktop) = std::env::var(XDG_CURRENT_DESKTOP) {
        for value in xdg_current_desktop
            .split(':')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            match value {
                "Unity" | "Deepin" | "GNOME" | "X-Cinnamon" | "Pantheon" | "XFCE"
                | "UKUI" | "LXQt" | "COSMIC" => return DesktopEnvironment::Other,
                DISPLAY_DESKTOP_KDE => return detect_kde_env_from_session_version(),
                _ => {}
            }
        }
    }

    if let Ok(desktop_session) = std::env::var(DESKTOP_SESSION) {
        let desktop_session = desktop_session.trim();
        match desktop_session {
            "deepin" | "gnome" | "mate" | "ukui" => return DesktopEnvironment::Other,
            "kde4" | "kde-plasma" => return DesktopEnvironment::Kde4,
            "kde" => {
                return if has_env_var(KDE_SESSION_VERSION) {
                    DesktopEnvironment::Kde4
                } else {
                    DesktopEnvironment::Kde3
                };
            }
            "xubuntu" => return DesktopEnvironment::Other,
            _ => {
                if desktop_session.contains("xfce") {
                    return DesktopEnvironment::Other;
                }
            }
        }
    }

    if has_env_var(GNOME_DESKTOP_SESSION_ID) {
        return DesktopEnvironment::Other;
    }
    if has_env_var(KDE_FULL_SESSION) {
        return if has_env_var(KDE_SESSION_VERSION) {
            DesktopEnvironment::Kde4
        } else {
            DesktopEnvironment::Kde3
        };
    }

    DesktopEnvironment::Other
}

fn detect_kde_env_from_session_version() -> DesktopEnvironment {
    match std::env::var(KDE_SESSION_VERSION)
        .ok()
        .as_deref()
        .map(str::trim)
    {
        Some("5") => DesktopEnvironment::Kde5,
        Some("6") => DesktopEnvironment::Kde6,
        _ => DesktopEnvironment::Kde4,
    }
}

fn has_env_var(name: &str) -> bool {
    std::env::var_os(name).is_some()
}

struct KWalletHandleGuard<'a> {
    conn: &'a DbusConnection,
    backend: KWalletService,
    handle: i32,
    app_name: &'a str,
}

impl Drop for KWalletHandleGuard<'_> {
    fn drop(&mut self) {
        let _ = kwallet_close(self.conn, self.backend, self.handle, self.app_name);
    }
}

fn kwallet_proxy<'a>(
    conn: &'a DbusConnection,
    backend: KWalletService,
) -> dbus::blocking::Proxy<&'a DbusConnection> {
    conn.with_proxy(
        backend.service_name(),
        backend.path(),
        Duration::from_millis(KWALLET_TIMEOUT_MS),
    )
}

fn init_kwallet_backend(
    backend: KWalletService,
) -> SecretStoreResult<(DbusConnection, String, String)> {
    let conn = DbusConnection::new_session().map_err(|err| {
        SecretStoreError::backend("failed to connect to Linux KWallet session bus", err)
    })?;
    let wallet_name = match kwallet_network_wallet(&conn, backend) {
        Ok(name) => name,
        Err(first_err) => {
            start_kwalletd(&conn, backend)?;
            kwallet_network_wallet(&conn, backend).map_err(|_| first_err)?
        }
    };
    let app_name = crate::config::APP_NAME.read().unwrap().clone();
    Ok((conn, app_name, wallet_name))
}

fn start_kwalletd(conn: &DbusConnection, backend: KWalletService) -> SecretStoreResult<()> {
    let proxy = conn.with_proxy(
        KWALLET_KLAUNCHER_SERVICE,
        KWALLET_KLAUNCHER_PATH,
        Duration::from_millis(KWALLET_TIMEOUT_MS),
    );
    let empty: Vec<String> = vec![];
    let (ret, _dbus_name, error, _pid): (i32, String, String, i32) = proxy
        .method_call(
            KWALLET_KLAUNCHER_INTERFACE,
            "start_service_by_desktop_name",
            (
                backend.daemon_name().to_owned(),
                empty.clone(),
                empty,
                String::new(),
                false,
            ),
        )
        .map_err(|err| SecretStoreError::backend("failed to start Linux KWallet daemon", err))?;
    if ret != 0 || !error.is_empty() {
        return Err(SecretStoreError::backend_message(
            "failed to start Linux KWallet daemon",
            format!(
                "{} returned error '{}' (code {})",
                backend.daemon_name(),
                error,
                ret
            ),
        ));
    }
    Ok(())
}

fn kwallet_network_wallet(
    conn: &DbusConnection,
    backend: KWalletService,
) -> SecretStoreResult<String> {
    let proxy = kwallet_proxy(conn, backend);
    let (enabled,): (bool,) = proxy
        .method_call(KWALLET_INTERFACE, "isEnabled", ())
        .map_err(|err| {
            SecretStoreError::backend("failed to query Linux KWallet enabled state", err)
        })?;
    if !enabled {
        return Err(SecretStoreError::backend_message(
            "Linux KWallet is disabled",
            format!("{} reports that KWallet is not enabled", backend.daemon_name()),
        ));
    }
    let (wallet_name,): (String,) = proxy
        .method_call(KWALLET_INTERFACE, "networkWallet", ())
        .map_err(|err| {
            SecretStoreError::backend("failed to query Linux KWallet network wallet", err)
        })?;
    if wallet_name.is_empty() {
        return Err(SecretStoreError::backend_message(
            "failed to query Linux KWallet network wallet",
            "KWallet returned an empty network wallet name",
        ));
    }
    Ok(wallet_name)
}

fn kwallet_open_wallet(
    conn: &DbusConnection,
    backend: KWalletService,
    wallet_name: &str,
    app_name: &str,
) -> SecretStoreResult<i32> {
    let proxy = kwallet_proxy(conn, backend);
    let (handle,): (i32,) = proxy
        .method_call(
            KWALLET_INTERFACE,
            "open",
            (wallet_name.to_owned(), 0_i64, app_name.to_owned()),
        )
        .map_err(|err| SecretStoreError::backend("failed to open Linux KWallet wallet", err))?;
    if handle == KWALLET_INVALID_HANDLE {
        return Err(SecretStoreError::backend_message(
            "failed to open Linux KWallet wallet",
            format!("{} returned an invalid wallet handle", backend.daemon_name()),
        ));
    }
    Ok(handle)
}

fn kwallet_has_folder(
    conn: &DbusConnection,
    backend: KWalletService,
    handle: i32,
    folder_name: &str,
    app_name: &str,
) -> SecretStoreResult<bool> {
    let proxy = kwallet_proxy(conn, backend);
    let (has_folder,): (bool,) = proxy
        .method_call(
            KWALLET_INTERFACE,
            "hasFolder",
            (handle, folder_name.to_owned(), app_name.to_owned()),
        )
        .map_err(|err| SecretStoreError::backend("failed to query Linux KWallet folder", err))?;
    Ok(has_folder)
}

fn kwallet_create_folder(
    conn: &DbusConnection,
    backend: KWalletService,
    handle: i32,
    folder_name: &str,
    app_name: &str,
) -> SecretStoreResult<()> {
    let proxy = kwallet_proxy(conn, backend);
    let (created,): (bool,) = proxy
        .method_call(
            KWALLET_INTERFACE,
            "createFolder",
            (handle, folder_name.to_owned(), app_name.to_owned()),
        )
        .map_err(|err| SecretStoreError::backend("failed to create Linux KWallet folder", err))?;
    if !created {
        return Err(SecretStoreError::backend_message(
            "failed to create Linux KWallet folder",
            format!("KWallet returned false for folder {folder_name}"),
        ));
    }
    Ok(())
}

fn kwallet_has_entry(
    conn: &DbusConnection,
    backend: KWalletService,
    handle: i32,
    folder_name: &str,
    key: &str,
    app_name: &str,
) -> SecretStoreResult<bool> {
    let proxy = kwallet_proxy(conn, backend);
    let (has_entry,): (bool,) = proxy
        .method_call(
            KWALLET_INTERFACE,
            "hasEntry",
            (
                handle,
                folder_name.to_owned(),
                key.to_owned(),
                app_name.to_owned(),
            ),
        )
        .map_err(|err| SecretStoreError::backend("failed to query Linux KWallet entry", err))?;
    Ok(has_entry)
}

fn kwallet_entry_type(
    conn: &DbusConnection,
    backend: KWalletService,
    handle: i32,
    folder_name: &str,
    key: &str,
    app_name: &str,
) -> SecretStoreResult<i32> {
    let proxy = kwallet_proxy(conn, backend);
    let (entry_type,): (i32,) = proxy
        .method_call(
            KWALLET_INTERFACE,
            "entryType",
            (
                handle,
                folder_name.to_owned(),
                key.to_owned(),
                app_name.to_owned(),
            ),
        )
        .map_err(|err| {
            SecretStoreError::backend("failed to query Linux KWallet entry type", err)
        })?;
    Ok(entry_type)
}

fn kwallet_remove_entry(
    conn: &DbusConnection,
    backend: KWalletService,
    handle: i32,
    folder_name: &str,
    key: &str,
    app_name: &str,
) -> SecretStoreResult<()> {
    let proxy = kwallet_proxy(conn, backend);
    let (ret,): (i32,) = proxy
        .method_call(
            KWALLET_INTERFACE,
            "removeEntry",
            (
                handle,
                folder_name.to_owned(),
                key.to_owned(),
                app_name.to_owned(),
            ),
        )
        .map_err(|err| SecretStoreError::backend("failed to remove Linux KWallet entry", err))?;
    if ret != 0 {
        return Err(SecretStoreError::backend_message(
            "failed to remove Linux KWallet entry",
            format!("KWallet removeEntry returned error code {ret}"),
        ));
    }
    Ok(())
}

fn kwallet_read_password(
    conn: &DbusConnection,
    backend: KWalletService,
    handle: i32,
    folder_name: &str,
    key: &str,
    app_name: &str,
) -> SecretStoreResult<String> {
    let proxy = kwallet_proxy(conn, backend);
    let (password,): (String,) = proxy
        .method_call(
            KWALLET_INTERFACE,
            "readPassword",
            (
                handle,
                folder_name.to_owned(),
                key.to_owned(),
                app_name.to_owned(),
            ),
        )
        .map_err(|err| SecretStoreError::backend("failed to read Linux KWallet password", err))?;
    Ok(password)
}

fn kwallet_write_password(
    conn: &DbusConnection,
    backend: KWalletService,
    handle: i32,
    folder_name: &str,
    key: &str,
    password: &str,
    app_name: &str,
) -> SecretStoreResult<()> {
    let proxy = kwallet_proxy(conn, backend);
    let (ret,): (i32,) = proxy
        .method_call(
            KWALLET_INTERFACE,
            "writePassword",
            (
                handle,
                folder_name.to_owned(),
                key.to_owned(),
                password.to_owned(),
                app_name.to_owned(),
            ),
        )
        .map_err(|err| SecretStoreError::backend("failed to write Linux KWallet password", err))?;
    if ret != 0 {
        return Err(SecretStoreError::backend_message(
            "failed to write Linux KWallet password",
            format!("KWallet writePassword returned error code {ret}"),
        ));
    }
    Ok(())
}

fn kwallet_close(
    conn: &DbusConnection,
    backend: KWalletService,
    handle: i32,
    app_name: &str,
) -> SecretStoreResult<()> {
    let proxy = kwallet_proxy(conn, backend);
    let (ret,): (i32,) = proxy
        .method_call(KWALLET_INTERFACE, "close", (handle, false, app_name.to_owned()))
        .map_err(|err| SecretStoreError::backend("failed to close Linux KWallet wallet", err))?;
    if ret != 0 {
        return Err(SecretStoreError::backend_message(
            "failed to close Linux KWallet wallet",
            format!("KWallet close returned error code {ret}"),
        ));
    }
    Ok(())
}

fn load_kwallet_secret_store_key(service: &str, account: &str) -> SecretStoreResult<Vec<u8>> {
    let backend = detect_kwallet_service();
    let (conn, app_name, wallet_name) = init_kwallet_backend(backend)?;
    let handle = kwallet_open_wallet(&conn, backend, &wallet_name, &app_name)?;
    let _guard = KWalletHandleGuard {
        conn: &conn,
        backend,
        handle,
        app_name: &app_name,
    };

    if !kwallet_has_folder(&conn, backend, handle, service, &app_name)? {
        return Err(SecretStoreError::NotFound);
    }
    if !kwallet_has_entry(&conn, backend, handle, service, account, &app_name)? {
        return Err(SecretStoreError::NotFound);
    }

    let entry_type = kwallet_entry_type(&conn, backend, handle, service, account, &app_name)?;
    if entry_type != KWALLET_ENTRY_TYPE_PASSWORD {
        return Err(SecretStoreError::backend_message(
            "failed to read Linux KWallet secret",
            format!(
                "unexpected entry type {} for folder {} key {}",
                entry_type, service, account
            ),
        ));
    }

    let encoded = kwallet_read_password(&conn, backend, handle, service, account, &app_name)?;
    if encoded.is_empty() {
        return Err(SecretStoreError::backend_message(
            "failed to read Linux KWallet secret",
            format!("empty password for folder {} key {}", service, account),
        ));
    }

    // We intentionally mirror Chromium's KWallet implementation and use
    // readPassword/writePassword string entries instead of KWallet stream
    // entries, so arbitrary bytes are base64-encoded on write and decoded on
    // read here.
    // Chromium refs:
    // - components/os_crypt/sync/kwallet_dbus.cc:327-390
    // - components/os_crypt/sync/key_storage_kwallet.cc:113-137
    // - https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/sync/kwallet_dbus.cc#327
    // - https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/sync/key_storage_kwallet.cc#113
    // Related wrapper discussion:
    // - https://github.com/open-source-cooperative/zbus-secret-service-keyring-store/blob/82b10682ca5afb2df9840941a290a3e038ef6c3c/src/lib.rs#L95
    BASE64_STANDARD.decode(encoded).map_err(|err| {
        SecretStoreError::backend("failed to decode Linux KWallet secret payload", err)
    })
}

fn store_kwallet_secret_store_key(
    service: &str,
    account: &str,
    secret: &[u8],
) -> SecretStoreResult<()> {
    let backend = detect_kwallet_service();
    let (conn, app_name, wallet_name) = init_kwallet_backend(backend)?;
    let handle = kwallet_open_wallet(&conn, backend, &wallet_name, &app_name)?;
    let _guard = KWalletHandleGuard {
        conn: &conn,
        backend,
        handle,
        app_name: &app_name,
    };

    if !kwallet_has_folder(&conn, backend, handle, service, &app_name)? {
        kwallet_create_folder(&conn, backend, handle, service, &app_name)?;
    }
    if kwallet_has_entry(&conn, backend, handle, service, account, &app_name)? {
        let entry_type = kwallet_entry_type(&conn, backend, handle, service, account, &app_name)?;
        if entry_type != KWALLET_ENTRY_TYPE_PASSWORD {
            kwallet_remove_entry(&conn, backend, handle, service, account, &app_name)?;
        }
    }

    let encoded = BASE64_STANDARD.encode(secret);
    kwallet_write_password(
        &conn,
        backend,
        handle,
        service,
        account,
        &encoded,
        &app_name,
    )
}

pub fn load_secret_store_key(service: &str, account: &str) -> SecretStoreResult<Vec<u8>> {
    // Secret Service refs used by the wrapper path below:
    // - org.freedesktop.Secret.Service.OpenSession / SearchItems / Unlock
    //   https://specifications.freedesktop.org/secret-service/latest/org.freedesktop.Secret.Service.html
    // - org.freedesktop.Secret.Item.GetSecret
    //   https://specifications.freedesktop.org/secret-service-spec/latest/org.freedesktop.Secret.Item.html
    let attrs = HashMap::from([("service", service), ("account", account)]);
    let ss = SecretService::connect(EncryptionType::Dh).map_err(|err| {
        SecretStoreError::backend("failed to connect to Linux Secret Service", err)
    })?;
    let search = ss.search_items(attrs).map_err(|err| {
        SecretStoreError::backend("failed to search Linux Secret Service items", err)
    })?;
    if !search.locked.is_empty() {
        let item_refs: Vec<&Item> = search.locked.iter().collect();
        ss.unlock_all(item_refs.as_slice()).map_err(|err| {
            SecretStoreError::backend("failed to unlock Linux Secret Service items", err)
        })?;
    }

    let mut saw_item = false;
    let mut last_error = None;
    for item in search.unlocked.iter().chain(search.locked.iter()) {
        saw_item = true;
        match item.get_secret() {
            Ok(secret) => return Ok(secret),
            Err(err) => last_error = Some(err.to_string()),
        }
    }

    if saw_item {
        Err(SecretStoreError::backend_message(
            "failed to read secret from Linux Secret Service",
            last_error.unwrap_or_else(|| "unknown secret read error".to_owned()),
        ))
    } else {
        Err(SecretStoreError::NotFound)
    }
}

pub fn store_secret_store_key(
    service: &str,
    account: &str,
    secret: &[u8],
) -> SecretStoreResult<()> {
    // Secret Service refs used by the wrapper path below:
    // - org.freedesktop.Secret.Service.OpenSession / ReadAlias / Unlock
    //   https://specifications.freedesktop.org/secret-service/latest/org.freedesktop.Secret.Service.html
    // - org.freedesktop.Secret.Collection.CreateItem
    //   https://specifications.freedesktop.org/secret-service-spec/latest/org.freedesktop.Secret.Collection.html
    let ss = SecretService::connect(EncryptionType::Dh).map_err(|err| {
        SecretStoreError::backend("failed to connect to Linux Secret Service", err)
    })?;
    let collection = ss.get_default_collection().map_err(|err| {
        SecretStoreError::backend("failed to get Linux Secret Service collection", err)
    })?;
    if collection.is_locked().map_err(|err| {
        SecretStoreError::backend("failed to query Linux Secret Service lock state", err)
    })? {
        collection.unlock().map_err(|err| {
            SecretStoreError::backend("failed to unlock Linux Secret Service collection", err)
        })?;
    }
    let attrs = HashMap::from([("service", service), ("account", account)]);
    let label = format!("{service} {account}");
    collection
        .create_item(&label, attrs, secret, true, "application/octet-stream")
        .map_err(|err| {
            SecretStoreError::backend("failed to create Linux Secret Service item", err)
        })?;
    Ok(())
}

/// Use Secret Service as the default Linux secret backend outside KDE.
///
/// Do not use the kernel keyutils persistent keyring for RustDesk's master key
/// or device-identity style secrets:
/// - it is not a durable application secret store and can disappear due to
///   kernel / login-session lifetime rules;
/// - a missing read here is especially dangerous because upper layers may treat
///   it as "secret lost" and regenerate a new master key, which then makes
///   previously encrypted local config unreadable;
/// - this project needs stable reads first, even if the desktop secret service
///   is not ideal in every Linux environment.
pub fn load_secret(service: &str, account: &str) -> SecretStoreResult<Vec<u8>> {
    if is_flatpak() {
        return load_flatpak_secret_store_key(service, account);
    }
    match linux_secret_backend() {
        LinuxSecretBackend::SecretService => load_secret_store_key(service, account),
        LinuxSecretBackend::KWallet(_) => load_kwallet_secret_store_key(service, account),
    }
}

pub fn store_secret(service: &str, account: &str, secret: &[u8]) -> SecretStoreResult<()> {
    if is_flatpak() {
        return store_flatpak_secret_store_key(service, account, secret);
    }
    match linux_secret_backend() {
        LinuxSecretBackend::SecretService => store_secret_store_key(service, account, secret),
        LinuxSecretBackend::KWallet(_) => store_kwallet_secret_store_key(service, account, secret),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_cmds_trim_newline() {
        assert_eq!(run_cmds_trim_newline("echo -n 123").unwrap(), "123");
        assert_eq!(run_cmds_trim_newline("echo 123").unwrap(), "123");
        assert_eq!(
            run_cmds_trim_newline("whoami").unwrap() + "\n",
            run_cmds("whoami").unwrap()
        );
    }

    /// Test get_home_dir_trusted: returns valid path and ignores HOME env var
    #[test]
    fn test_get_home_dir_trusted() {
        let original_home = std::env::var("HOME").ok();

        // Set HOME to a fake/malicious path
        std::env::set_var("HOME", "/tmp/fake_malicious_home");
        let result = get_home_dir_trusted();

        // Restore original HOME
        match original_home {
            Some(home) => std::env::set_var("HOME", home),
            None => std::env::remove_var("HOME"),
        }

        // Verify: returns valid path that is NOT the fake HOME
        if let Some(path) = result {
            assert!(path.is_absolute(), "Path should be absolute: {:?}", path);
            assert!(path.is_dir(), "Path should be a directory: {:?}", path);
            assert_ne!(
                path.to_string_lossy(),
                "/tmp/fake_malicious_home",
                "Should not use HOME env var"
            );
        }
    }

    /// Test shell_quote with normal strings
    #[test]
    fn test_shell_quote_normal() {
        assert_eq!(shell_quote("hello"), "'hello'");
        assert_eq!(shell_quote("/home/user"), "'/home/user'");
    }

    /// Test shell_quote with spaces
    #[test]
    fn test_shell_quote_spaces() {
        assert_eq!(shell_quote("/home/my user/file"), "'/home/my user/file'");
        assert_eq!(shell_quote("path with spaces"), "'path with spaces'");
    }

    /// Test shell_quote with single quotes (the tricky case)
    #[test]
    fn test_shell_quote_single_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("don't stop"), "'don'\\''t stop'");
    }

    /// Test shell_quote with shell metacharacters
    #[test]
    fn test_shell_quote_metacharacters() {
        // These should all be safely quoted
        assert_eq!(shell_quote("test;rm -rf /"), "'test;rm -rf /'");
        assert_eq!(shell_quote("$(whoami)"), "'$(whoami)'");
        assert_eq!(shell_quote("`id`"), "'`id`'");
        assert_eq!(shell_quote("a && b"), "'a && b'");
        assert_eq!(shell_quote("a | b"), "'a | b'");
    }

    #[test]
    fn test_flatpak_secret_derivation_is_stable() {
        let a = derive_flatpak_secret("RustDesk Safe Storage", "RustDesk", b"portal-secret");
        let b = derive_flatpak_secret("RustDesk Safe Storage", "RustDesk", b"portal-secret");
        let c = derive_flatpak_secret("RustDesk Safe Storage", "RustDesk 2", b"portal-secret");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn test_detect_kwallet_service_from_xdg_current_desktop() {
        let original_xdg_current_desktop = std::env::var(XDG_CURRENT_DESKTOP).ok();
        let original_desktop_session = std::env::var(DESKTOP_SESSION).ok();
        let original_kde_session_version = std::env::var(KDE_SESSION_VERSION).ok();
        let original_kde_full_session = std::env::var(KDE_FULL_SESSION).ok();
        let original_gnome_desktop_session_id = std::env::var(GNOME_DESKTOP_SESSION_ID).ok();

        std::env::set_var(XDG_CURRENT_DESKTOP, DISPLAY_DESKTOP_KDE);
        std::env::remove_var(DESKTOP_SESSION);
        std::env::remove_var(KDE_FULL_SESSION);
        std::env::remove_var(GNOME_DESKTOP_SESSION_ID);

        std::env::set_var(KDE_SESSION_VERSION, "6");
        assert_eq!(detect_kwallet_service(), KWalletService::KWallet6);
        assert_eq!(
            detect_desktop_environment(),
            DesktopEnvironment::Kde6
        );

        std::env::set_var(KDE_SESSION_VERSION, "5");
        assert_eq!(detect_kwallet_service(), KWalletService::KWallet5);
        assert_eq!(
            detect_desktop_environment(),
            DesktopEnvironment::Kde5
        );

        std::env::set_var(KDE_SESSION_VERSION, "4");
        assert_eq!(detect_kwallet_service(), KWalletService::Legacy);
        assert_eq!(
            detect_desktop_environment(),
            DesktopEnvironment::Kde4
        );

        match original_xdg_current_desktop {
            Some(value) => std::env::set_var(XDG_CURRENT_DESKTOP, value),
            None => std::env::remove_var(XDG_CURRENT_DESKTOP),
        }
        match original_desktop_session {
            Some(value) => std::env::set_var(DESKTOP_SESSION, value),
            None => std::env::remove_var(DESKTOP_SESSION),
        }
        match original_kde_session_version {
            Some(value) => std::env::set_var(KDE_SESSION_VERSION, value),
            None => std::env::remove_var(KDE_SESSION_VERSION),
        }
        match original_kde_full_session {
            Some(value) => std::env::set_var(KDE_FULL_SESSION, value),
            None => std::env::remove_var(KDE_FULL_SESSION),
        }
        match original_gnome_desktop_session_id {
            Some(value) => std::env::set_var(GNOME_DESKTOP_SESSION_ID, value),
            None => std::env::remove_var(GNOME_DESKTOP_SESSION_ID),
        }
    }

    #[test]
    fn test_detect_desktop_environment_from_desktop_session() {
        let original_xdg_current_desktop = std::env::var(XDG_CURRENT_DESKTOP).ok();
        let original_desktop_session = std::env::var(DESKTOP_SESSION).ok();
        let original_kde_session_version = std::env::var(KDE_SESSION_VERSION).ok();
        let original_kde_full_session = std::env::var(KDE_FULL_SESSION).ok();
        let original_gnome_desktop_session_id = std::env::var(GNOME_DESKTOP_SESSION_ID).ok();

        std::env::remove_var(XDG_CURRENT_DESKTOP);
        std::env::remove_var(KDE_FULL_SESSION);
        std::env::remove_var(GNOME_DESKTOP_SESSION_ID);

        std::env::set_var(DESKTOP_SESSION, "kde");
        std::env::remove_var(KDE_SESSION_VERSION);
        assert_eq!(
            detect_desktop_environment(),
            DesktopEnvironment::Kde3
        );
        assert_eq!(linux_secret_backend(), LinuxSecretBackend::SecretService);

        std::env::set_var(KDE_SESSION_VERSION, "6");
        assert_eq!(
            detect_desktop_environment(),
            DesktopEnvironment::Kde4
        );
        assert_eq!(detect_kwallet_service(), KWalletService::Legacy);
        assert!(matches!(
            linux_secret_backend(),
            LinuxSecretBackend::KWallet(KWalletService::Legacy)
        ));

        std::env::set_var(DESKTOP_SESSION, "gnome");
        assert_eq!(
            detect_desktop_environment(),
            DesktopEnvironment::Other
        );
        assert_eq!(linux_secret_backend(), LinuxSecretBackend::SecretService);

        match original_xdg_current_desktop {
            Some(value) => std::env::set_var(XDG_CURRENT_DESKTOP, value),
            None => std::env::remove_var(XDG_CURRENT_DESKTOP),
        }
        match original_desktop_session {
            Some(value) => std::env::set_var(DESKTOP_SESSION, value),
            None => std::env::remove_var(DESKTOP_SESSION),
        }
        match original_kde_session_version {
            Some(value) => std::env::set_var(KDE_SESSION_VERSION, value),
            None => std::env::remove_var(KDE_SESSION_VERSION),
        }
        match original_kde_full_session {
            Some(value) => std::env::set_var(KDE_FULL_SESSION, value),
            None => std::env::remove_var(KDE_FULL_SESSION),
        }
        match original_gnome_desktop_session_id {
            Some(value) => std::env::set_var(GNOME_DESKTOP_SESSION_ID, value),
            None => std::env::remove_var(GNOME_DESKTOP_SESSION_ID),
        }
    }
}
