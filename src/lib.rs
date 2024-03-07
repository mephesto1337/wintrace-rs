use serde::Serialize;
use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    io::Write,
    ptr,
    sync::{
        atomic::{AtomicPtr, Ordering},
        Mutex,
    },
};
use windows::{
    core::{Error, HRESULT, PCSTR},
    Win32::Foundation::S_OK,
};

#[macro_export]
macro_rules! dlogln {
    ($dbg:ident, $($arg:tt)*) => {{
        $dbg.logln(format!($($arg)*))
    }};
}

pub mod debugger;
pub mod helpers;
pub mod trace_io;

use helpers::{expand_env, wrap};

static LOG_FILE: AtomicPtr<Mutex<File>> = AtomicPtr::new(ptr::null_mut());
pub fn save_call<S: Serialize>(obj: &S) {
    let mut line = serde_json::to_string(obj).unwrap();
    line.push('\n');
    if let Ok(mut file) = unsafe { &*LOG_FILE.load(Ordering::Relaxed) }.lock() {
        let _ = file.write_all(line.as_bytes());
    }
}

#[no_mangle]
pub extern "C" fn wintrace(raw_client: *mut c_void, args: PCSTR) -> HRESULT {
    wrap(raw_client, args, "wintrace", |dbg, _| {
        dbg.retprobe("KERNELBASE!CreateFileA")?;
        dbg.retprobe("KERNELBASE!CreateFileW")?;
        dbg.retprobe("kernel32!ReadFile")?;
        dbg.probe("kernel32!WriteFile")?;
        dbg.probe("kernel32!CloseHandle")?;

        Ok(())
    })
}

/// The DebugExtensionInitialize callback function is called by the engine after
/// loading a DbgEng extension DLL. https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nc-dbgeng-pdebug_extension_initialize
#[no_mangle]
extern "C" fn DebugExtensionInitialize(_version: *mut u32, _flags: *mut u32) -> HRESULT {
    let f = match OpenOptions::new()
        .append(true)
        .create(true)
        .open(expand_env(r"%USERPROFILE%\wintrace.json"))
    {
        Ok(f) => f,
        Err(e) => {
            let ms_e: Error = e.into();
            return ms_e.into();
        }
    };
    LOG_FILE.store(Box::into_raw(Box::new(Mutex::new(f))), Ordering::Relaxed);
    trace_io::init();
    S_OK
}

#[no_mangle]
extern "C" fn DebugExtensionUninitialize() {
    trace_io::deinit();
    let file_ptr = LOG_FILE.swap(ptr::null_mut(), Ordering::Relaxed);
    if !file_ptr.is_null() {
        let _ = unsafe { Box::from_raw(file_ptr) };
    }
}
