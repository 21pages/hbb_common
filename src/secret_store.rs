use crate::{
    config::{Config, APP_NAME},
    log,
};
use sodiumoxide::base64;
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    sync::OnceLock,
};

const MASTER_KEY_LEN: usize = sodiumoxide::crypto::secretbox::KEYBYTES;

static MASTER_KEY: OnceLock<Vec<u8>> = OnceLock::new();

pub fn get_or_create_master_key() -> Result<Vec<u8>, ()> {
    if let Some(key) = MASTER_KEY.get() {
        return Ok(key.clone());
    }

    let key = load_platform_key()
        .or_else(load_fallback_file_key)
        .or_else(|| {
            let key = sodiumoxide::randombytes::randombytes(MASTER_KEY_LEN);
            if store_platform_key(&key).is_none() && store_fallback_file_key(&key).is_none() {
                log::error!("Failed to persist generated master key");
                return None;
            }
            Some(key)
        })
        .ok_or(())?;

    let _ = MASTER_KEY.set(key.clone());
    Ok(key)
}

#[cfg(target_os = "macos")]
fn load_platform_key() -> Option<Vec<u8>> {
    use std::process::Command;

    let output = Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            &service_name(),
            "-a",
            &account_name(),
            "-w",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    decode_key(output.stdout)
}

#[cfg(target_os = "linux")]
fn load_platform_key() -> Option<Vec<u8>> {
    use std::process::Command;

    let output = Command::new("secret-tool")
        .args([
            "lookup",
            "service",
            &service_name(),
            "account",
            &account_name(),
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    decode_key(output.stdout)
}

#[cfg(target_os = "windows")]
fn load_platform_key() -> Option<Vec<u8>> {
    dpapi_read_from_file().or_else(load_fallback_file_key)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn load_platform_key() -> Option<Vec<u8>> {
    None
}

#[cfg(target_os = "macos")]
fn store_platform_key(key: &[u8]) -> Option<()> {
    use std::process::Command;

    let encoded = encode_key(key);
    let output = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-s",
            &service_name(),
            "-a",
            &account_name(),
            "-w",
            &encoded,
        ])
        .output()
        .ok()?;
    if output.status.success() {
        Some(())
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn store_platform_key(key: &[u8]) -> Option<()> {
    use std::process::{Command, Stdio};

    let encoded = encode_key(key);
    let mut child = Command::new("secret-tool")
        .args([
            "store",
            "--label",
            &label_name(),
            "service",
            &service_name(),
            "account",
            &account_name(),
        ])
        .stdin(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.as_mut()?.write_all(encoded.as_bytes()).ok()?;
    let status = child.wait().ok()?;
    if status.success() {
        Some(())
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
fn store_platform_key(key: &[u8]) -> Option<()> {
    dpapi_write_to_file(key).or_else(|| store_fallback_file_key(key))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn store_platform_key(_key: &[u8]) -> Option<()> {
    None
}

fn load_fallback_file_key() -> Option<Vec<u8>> {
    let mut file = fs::File::open(fallback_key_path()).ok()?;
    let mut encoded = Vec::new();
    file.read_to_end(&mut encoded).ok()?;
    decode_key(encoded)
}

fn store_fallback_file_key(key: &[u8]) -> Option<()> {
    let path = fallback_key_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok()?;
    }
    let mut file = fs::File::create(&path).ok()?;
    file.write_all(encode_key(key).as_bytes()).ok()?;
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).ok()?;
    }
    Some(())
}

fn fallback_key_path() -> PathBuf {
    Config::path(format!("{}_master_key", APP_NAME.read().unwrap().clone()))
}

fn service_name() -> String {
    format!("{}.config-master-key", APP_NAME.read().unwrap().clone())
}

#[cfg(target_os = "linux")]
fn label_name() -> String {
    format!("{} Config Master Key", APP_NAME.read().unwrap().clone())
}

fn account_name() -> String {
    whoami::username().trim_end_matches('\0').to_owned()
}

fn encode_key(key: &[u8]) -> String {
    base64::encode(key, base64::Variant::Original)
}

fn decode_key(buf: Vec<u8>) -> Option<Vec<u8>> {
    let s = String::from_utf8(buf).ok()?;
    let s = s.trim();
    let decoded = base64::decode(s.as_bytes(), base64::Variant::Original).ok()?;
    (decoded.len() == MASTER_KEY_LEN).then_some(decoded)
}

#[cfg(target_os = "windows")]
fn dpapi_write_to_file(key: &[u8]) -> Option<()> {
    use std::{mem, ptr};
    use winapi::shared::minwindef::DWORD;
    use winapi::um::{dpapi::CryptProtectData, winbase::LocalFree, wincrypt::DATA_BLOB};

    let mut in_blob = DATA_BLOB {
        cbData: key.len() as DWORD,
        pbData: key.as_ptr() as *mut u8,
    };
    let mut out_blob: DATA_BLOB = unsafe { mem::zeroed() };
    let ok = unsafe {
        CryptProtectData(
            &mut in_blob,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return None;
    }
    let encrypted =
        unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec() };
    unsafe {
        LocalFree(out_blob.pbData as _);
    }
    let path = fallback_key_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok()?;
    }
    fs::write(path, encrypted).ok()?;
    Some(())
}

#[cfg(target_os = "windows")]
fn dpapi_read_from_file() -> Option<Vec<u8>> {
    use std::{mem, ptr};
    use winapi::shared::minwindef::DWORD;
    use winapi::um::{dpapi::CryptUnprotectData, winbase::LocalFree, wincrypt::DATA_BLOB};

    let encrypted = fs::read(fallback_key_path()).ok()?;
    let mut in_blob = DATA_BLOB {
        cbData: encrypted.len() as DWORD,
        pbData: encrypted.as_ptr() as *mut u8,
    };
    let mut out_blob: DATA_BLOB = unsafe { mem::zeroed() };
    let ok = unsafe {
        CryptUnprotectData(
            &mut in_blob,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return None;
    }
    let decrypted =
        unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec() };
    unsafe {
        LocalFree(out_blob.pbData as _);
    }
    (decrypted.len() == MASTER_KEY_LEN).then_some(decrypted)
}
