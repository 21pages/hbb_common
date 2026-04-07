use crate::secret_store::{SecretStoreError, SecretStoreResult};
use std::{
    collections::VecDeque,
    convert::TryInto,
    fs, ptr,
    sync::{Arc, Mutex},
    time::Instant,
};
use winapi::{
    shared::minwindef::{DWORD, FALSE, TRUE},
    um::{
        handleapi::CloseHandle,
        pdh::{
            PdhAddEnglishCounterA, PdhCloseQuery, PdhCollectQueryData, PdhCollectQueryDataEx,
            PdhGetFormattedCounterValue, PdhOpenQueryA, PDH_FMT_COUNTERVALUE, PDH_FMT_DOUBLE,
            PDH_HCOUNTER, PDH_HQUERY,
        },
        synchapi::{CreateEventA, WaitForSingleObject},
        sysinfoapi::VerSetConditionMask,
        winbase::{VerifyVersionInfoW, INFINITE, WAIT_OBJECT_0},
        winnt::{
            HANDLE, OSVERSIONINFOEXW, VER_BUILDNUMBER, VER_GREATER_EQUAL, VER_MAJORVERSION,
            VER_MINORVERSION, VER_SERVICEPACKMAJOR, VER_SERVICEPACKMINOR,
        },
    },
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{LocalFree, ERROR_NOT_FOUND, HLOCAL},
        Security::{
            Credentials::{
                CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
                CRED_TYPE_GENERIC,
            },
            Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB},
        },
    },
};

lazy_static::lazy_static! {
    static ref CPU_USAGE_ONE_MINUTE: Arc<Mutex<Option<(f64, Instant)>>> = Arc::new(Mutex::new(None));
}

// https://github.com/mgostIH/process_list/blob/master/src/windows/mod.rs
#[repr(transparent)]
pub struct RAIIHandle(pub HANDLE);

impl Drop for RAIIHandle {
    fn drop(&mut self) {
        // This never gives problem except when running under a debugger.
        unsafe { CloseHandle(self.0) };
    }
}

#[repr(transparent)]
pub(self) struct RAIIPDHQuery(pub PDH_HQUERY);

impl Drop for RAIIPDHQuery {
    fn drop(&mut self) {
        unsafe { PdhCloseQuery(self.0) };
    }
}

pub fn start_cpu_performance_monitor() {
    // Code from:
    // https://learn.microsoft.com/en-us/windows/win32/perfctrs/collecting-performance-data
    // https://learn.microsoft.com/en-us/windows/win32/api/pdh/nf-pdh-pdhcollectquerydataex
    // Why value lower than taskManager:
    // https://aaron-margosis.medium.com/task-managers-cpu-numbers-are-all-but-meaningless-2d165b421e43
    // Therefore we should compare with Precess Explorer rather than taskManager

    let f = || unsafe {
        // load avg or cpu usage, test with prime95.
        // Prefer cpu usage because we can get accurate value from Precess Explorer.
        // const COUNTER_PATH: &'static str = "\\System\\Processor Queue Length\0";
        const COUNTER_PATH: &'static str = "\\Processor(_total)\\% Processor Time\0";
        const SAMPLE_INTERVAL: DWORD = 2; // 2 second

        let mut ret;
        let mut query: PDH_HQUERY = std::mem::zeroed();
        ret = PdhOpenQueryA(std::ptr::null() as _, 0, &mut query);
        if ret != 0 {
            log::error!("PdhOpenQueryA failed: 0x{:X}", ret);
            return;
        }
        let _query = RAIIPDHQuery(query);
        let mut counter: PDH_HCOUNTER = std::mem::zeroed();
        ret = PdhAddEnglishCounterA(query, COUNTER_PATH.as_ptr() as _, 0, &mut counter);
        if ret != 0 {
            log::error!("PdhAddEnglishCounterA failed: 0x{:X}", ret);
            return;
        }
        ret = PdhCollectQueryData(query);
        if ret != 0 {
            log::error!("PdhCollectQueryData failed: 0x{:X}", ret);
            return;
        }
        let mut _counter_type: DWORD = 0;
        let mut counter_value: PDH_FMT_COUNTERVALUE = std::mem::zeroed();
        let event = CreateEventA(std::ptr::null_mut(), FALSE, FALSE, std::ptr::null() as _);
        if event.is_null() {
            log::error!("CreateEventA failed");
            return;
        }
        let _event: RAIIHandle = RAIIHandle(event);
        ret = PdhCollectQueryDataEx(query, SAMPLE_INTERVAL, event);
        if ret != 0 {
            log::error!("PdhCollectQueryDataEx failed: 0x{:X}", ret);
            return;
        }

        let mut queue: VecDeque<f64> = VecDeque::new();
        let mut recent_valid: VecDeque<bool> = VecDeque::new();
        loop {
            // latest one minute
            if queue.len() == 31 {
                queue.pop_front();
            }
            if recent_valid.len() == 31 {
                recent_valid.pop_front();
            }
            // allow get value within one minute
            if queue.len() > 0 && recent_valid.iter().filter(|v| **v).count() > queue.len() / 2 {
                let sum: f64 = queue.iter().map(|f| f.to_owned()).sum();
                let avg = sum / (queue.len() as f64);
                *CPU_USAGE_ONE_MINUTE.lock().unwrap() = Some((avg, Instant::now()));
            } else {
                *CPU_USAGE_ONE_MINUTE.lock().unwrap() = None;
            }
            if WAIT_OBJECT_0 != WaitForSingleObject(event, INFINITE) {
                recent_valid.push_back(false);
                continue;
            }
            if PdhGetFormattedCounterValue(
                counter,
                PDH_FMT_DOUBLE,
                &mut _counter_type,
                &mut counter_value,
            ) != 0
                || counter_value.CStatus != 0
            {
                recent_valid.push_back(false);
                continue;
            }
            queue.push_back(counter_value.u.doubleValue().clone());
            recent_valid.push_back(true);
        }
    };
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::thread::spawn(f);
    });
}

pub fn cpu_uage_one_minute() -> Option<f64> {
    let v = CPU_USAGE_ONE_MINUTE.lock().unwrap().clone();
    if let Some((v, instant)) = v {
        if instant.elapsed().as_secs() < 30 {
            return Some(v);
        }
    }
    None
}

pub fn sync_cpu_usage(cpu_usage: Option<f64>) {
    let v = match cpu_usage {
        Some(cpu_usage) => Some((cpu_usage, Instant::now())),
        None => None,
    };
    *CPU_USAGE_ONE_MINUTE.lock().unwrap() = v;
    log::info!("cpu usage synced: {:?}", cpu_usage);
}

// https://learn.microsoft.com/en-us/windows/win32/sysinfo/targeting-your-application-at-windows-8-1
// https://github.com/nodejs/node-convergence-archive/blob/e11fe0c2777561827cdb7207d46b0917ef3c42a7/deps/uv/src/win/util.c#L780
pub fn is_windows_version_or_greater(
    os_major: u32,
    os_minor: u32,
    build_number: u32,
    service_pack_major: u32,
    service_pack_minor: u32,
) -> bool {
    let mut osvi: OSVERSIONINFOEXW = unsafe { std::mem::zeroed() };
    osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as DWORD;
    osvi.dwMajorVersion = os_major as _;
    osvi.dwMinorVersion = os_minor as _;
    osvi.dwBuildNumber = build_number as _;
    osvi.wServicePackMajor = service_pack_major as _;
    osvi.wServicePackMinor = service_pack_minor as _;

    let result = unsafe {
        let mut condition_mask = 0;
        let op = VER_GREATER_EQUAL;
        condition_mask = VerSetConditionMask(condition_mask, VER_MAJORVERSION, op);
        condition_mask = VerSetConditionMask(condition_mask, VER_MINORVERSION, op);
        condition_mask = VerSetConditionMask(condition_mask, VER_BUILDNUMBER, op);
        condition_mask = VerSetConditionMask(condition_mask, VER_SERVICEPACKMAJOR, op);
        condition_mask = VerSetConditionMask(condition_mask, VER_SERVICEPACKMINOR, op);

        VerifyVersionInfoW(
            &mut osvi as *mut OSVERSIONINFOEXW,
            VER_MAJORVERSION
                | VER_MINORVERSION
                | VER_BUILDNUMBER
                | VER_SERVICEPACKMAJOR
                | VER_SERVICEPACKMINOR,
            condition_mask,
        )
    };

    result == TRUE
}

struct CredentialGuard(*mut CREDENTIALW);

impl Drop for CredentialGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CredFree(self.0 as _) };
        }
    }
}

pub fn load_secret(service: &str, account: &str) -> SecretStoreResult<Vec<u8>> {
    load_secret_credential(service, account)
}

pub fn store_secret(service: &str, account: &str, secret: &[u8]) -> SecretStoreResult<()> {
    store_secret_credential(service, account, secret)
}

pub fn load_secret_credential(service: &str, account: &str) -> SecretStoreResult<Vec<u8>> {
    let target = to_wide_null(&credential_target_name(service, account));
    let mut credential = ptr::null_mut();
    match unsafe {
        CredReadW(
            PCWSTR::from_raw(target.as_ptr()),
            CRED_TYPE_GENERIC,
            None,
            &mut credential,
        )
    } {
        Ok(_) => {}
        Err(err) if err.code() == ERROR_NOT_FOUND.to_hresult() => {
            return Err(SecretStoreError::NotFound);
        }
        Err(err) => {
            return Err(SecretStoreError::backend(
                "failed to read Windows Credential Manager secret",
                err,
            ));
        }
    }
    if credential.is_null() {
        return Err(SecretStoreError::backend_message(
            "failed to read Windows Credential Manager secret",
            "CredReadW returned a null credential pointer",
        ));
    }

    let _guard = CredentialGuard(credential);
    let credential = unsafe { &*credential };
    if credential.CredentialBlob.is_null() {
        return Ok(Vec::new());
    }

    Ok(unsafe {
        std::slice::from_raw_parts(
            credential.CredentialBlob,
            credential.CredentialBlobSize as usize,
        )
    }
    .to_vec())
}

pub fn store_secret_credential(
    service: &str,
    account: &str,
    secret: &[u8],
) -> SecretStoreResult<()> {
    let target = to_wide_null(&credential_target_name(service, account));
    let username = to_wide_null(account);
    let mut credential = CREDENTIALW::default();
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = PWSTR::from_raw(target.as_ptr() as *mut _);
    credential.CredentialBlobSize = secret.len().try_into().map_err(|_| {
        SecretStoreError::backend_message(
            "failed to prepare Windows Credential Manager secret",
            "secret is too large for CredentialBlobSize",
        )
    })?;
    credential.CredentialBlob = secret.as_ptr() as *mut u8;
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    credential.UserName = PWSTR::from_raw(username.as_ptr() as *mut _);
    unsafe { CredWriteW(&credential, 0) }.map_err(|err| {
        SecretStoreError::backend("failed to write Windows Credential Manager secret", err)
    })?;
    Ok(())
}

pub fn dpapi_write_file(path: &std::path::Path, key: &[u8]) -> SecretStoreResult<()> {
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: key.len().try_into().map_err(|_| {
            SecretStoreError::backend_message(
                "failed to prepare Windows DPAPI plaintext blob",
                "input is too large for CRYPT_INTEGER_BLOB",
            )
        })?,
        pbData: key.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB::default();
    unsafe { CryptProtectData(&in_blob, PCWSTR::null(), None, None, None, 0, &mut out_blob) }
        .map_err(|err| SecretStoreError::backend("failed to encrypt Windows DPAPI payload", err))?;
    let encrypted = blob_to_vec(&out_blob)?;
    free_local_buffer(out_blob.pbData);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            SecretStoreError::backend("failed to create Windows DPAPI output directory", err)
        })?;
    }
    fs::write(path, encrypted).map_err(|err| {
        SecretStoreError::backend("failed to write Windows DPAPI output file", err)
    })?;
    Ok(())
}

pub fn dpapi_read_file(path: &std::path::Path, expected_len: usize) -> SecretStoreResult<Vec<u8>> {
    let encrypted = fs::read(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            SecretStoreError::NotFound
        } else {
            SecretStoreError::backend("failed to read Windows DPAPI input file", err)
        }
    })?;
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: encrypted.len().try_into().map_err(|_| {
            SecretStoreError::backend_message(
                "failed to prepare Windows DPAPI ciphertext blob",
                "input is too large for CRYPT_INTEGER_BLOB",
            )
        })?,
        pbData: encrypted.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB::default();
    unsafe { CryptUnprotectData(&in_blob, None, None, None, None, 0, &mut out_blob) }
        .map_err(|err| SecretStoreError::backend("failed to decrypt Windows DPAPI payload", err))?;
    let decrypted = blob_to_vec(&out_blob)?;
    free_local_buffer(out_blob.pbData);
    if decrypted.len() == expected_len {
        Ok(decrypted)
    } else {
        Err(SecretStoreError::InvalidLength {
            expected: expected_len,
            actual: decrypted.len(),
        })
    }
}

fn blob_to_vec(blob: &CRYPT_INTEGER_BLOB) -> SecretStoreResult<Vec<u8>> {
    if blob.cbData == 0 {
        return Ok(Vec::new());
    }
    if blob.pbData.is_null() {
        Err(SecretStoreError::backend_message(
            "failed to read Windows blob",
            "blob pointer was null",
        ))
    } else {
        Ok(unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec() })
    }
}

fn free_local_buffer(buffer: *mut u8) {
    if !buffer.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(buffer.cast())));
        }
    }
}

fn credential_target_name(service: &str, account: &str) -> String {
    format!("{service}:{account}")
}

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
