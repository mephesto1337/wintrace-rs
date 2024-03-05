use base64::{prelude::BASE64_STANDARD, Engine};
use serde::Serialize;
use std::{
    borrow::Cow,
    collections::BTreeMap,
    ffi::c_void,
    ptr,
    sync::{
        atomic::{AtomicPtr, Ordering},
        RwLock,
    },
};
use windows::{
    core::{IUnknown, Interface, Result, HRESULT, PCSTR},
    Win32::{
        Foundation::{E_ABORT, S_OK},
        System::SystemServices::DLL_PROCESS_ATTACH,
    },
};

#[macro_export]
macro_rules! dlogln {
    ($dbg:ident, $($arg:tt)*) => {{
        $dbg.logln(format!($($arg)*))
    }};
}

mod debugger;

static HANDLES: AtomicPtr<RwLock<BTreeMap<u64, String>>> = AtomicPtr::new(ptr::null_mut());

#[ctor::ctor]
fn initialize_handles() {
    let handles = Box::into_raw(Box::default());
    HANDLES.store(handles, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn DllMain(_hinst: isize, reason: u32, _reserved: isize) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        initialize_handles();
    }
    1
}

fn get_handles() -> &'static RwLock<BTreeMap<u64, String>> {
    let handle = HANDLES.load(Ordering::Relaxed);
    assert_ne!(handle, ptr::null_mut(), "HANDLE has not been initialized");

    unsafe { &*handle }
}

#[derive(Debug, Serialize)]
struct FuncCall<'a> {
    pub funcname: Cow<'a, str>,
    pub buffer: Option<Cow<'a, str>>,
    pub handle: u64,
    pub filename: Option<Cow<'a, str>>,
}

pub use debugger::Debugger;

fn wrap<F>(raw_client: *mut c_void, args: PCSTR, callback: F) -> HRESULT
where
    F: FnOnce(&Debugger, String) -> Result<()>,
{
    let args = unsafe { args.to_string() }.unwrap_or_default();
    let Some(client) = (unsafe { IUnknown::from_raw_borrowed(&raw_client) }) else {
        return E_ABORT;
    };

    let Ok(dbg) = Debugger::new(client) else {
        return E_ABORT;
    };

    if let Err(e) = callback(&dbg, args) {
        e.code()
    } else {
        S_OK
    }
}

macro_rules! extract_next_args {
    ($parts:expr, $label:ident) => {
        $parts
            .next()
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .ok_or_else(|| {
                ::windows::core::Error::new(
                    ::windows::Win32::Foundation::E_INVALIDARG,
                    concat!("Cannot extract '", stringify!($label), "'"),
                )
            })
    };
}

#[no_mangle]
pub extern "C" fn trace_createfilew(raw_client: *mut c_void, args: PCSTR) -> HRESULT {
    wrap(raw_client, args, |dbg, args| -> Result<()> {
        dlogln!(dbg, "Inside 'trace_createfilew' {args:?}");
        if args.is_empty() {
            let filename_addr = dbg.get_arg(0)?;
            let bp = dbg.add_breakpoint(
                "@$ra",
                Some(format!("!trace_createfilew {filename_addr:x}")),
            )?;
            bp.oneshot()?;
        } else {
            let mut parts = args.split_whitespace();
            let filename_addr = extract_next_args!(parts, filename)?;
            let filename = dbg.read_wstring(filename_addr)?;
            let val = dbg.get_return_value()?;
            let fc = FuncCall {
                funcname: "CreateFileW".into(),
                buffer: None,
                filename: Some(filename.as_str().into()),
                handle: val,
            };
            dbg.logln(serde_json::to_string(&fc).unwrap());
            if let Ok(mut h) = get_handles().write() {
                h.insert(val, filename);
            } else {
                dlogln!(dbg, "Cannot monitor handle 0x{val:x} / {filename}");
            }
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn trace_read(raw_client: *mut c_void, args: PCSTR) -> HRESULT {
    wrap(raw_client, args, |dbg, args| -> Result<()> {
        dlogln!(dbg, "Inside 'trace_read' {args:?}");
        if args.is_empty() {
            let raw_handle = dbg.get_arg(0)?;
            let buffer_addr = dbg.get_arg(1)?;
            let buffer_size = dbg.get_arg(2)? as usize;
            let buffer_len_addr = dbg.get_arg(3)?;
            let bp = dbg.add_breakpoint(
                "@$ra",
                Some(format!(
                    "!trace_read {raw_handle:x} {buffer_addr:x} {buffer_len_addr:x} {buffer_size:x}"
                )),
            )?;
            bp.oneshot()?;
        } else {
            let mut parts = args.split_whitespace();
            let raw_handle = extract_next_args!(parts, raw_handle)?;
            let buffer_addr = extract_next_args!(parts, buffer_addr)?;
            let buffer_size = extract_next_args!(parts, buffer_size)? as usize;
            let buffer_len_addr = extract_next_args!(parts, buffer_len_addr)?;
            let mut buflen = 0;
            let buffer_size = if let Ok(()) = unsafe { dbg.read_into(buffer_len_addr, &mut buflen) }
            {
                buflen as usize
            } else {
                buffer_size
            };
            let mut buf = vec![0u8; buffer_size];
            dbg.read_memory_exact(buffer_addr, &mut buf[..])?;

            let filename = get_handles()
                .read()
                .ok()
                .and_then(|h| h.get(&raw_handle).cloned())
                .map(Cow::Owned);
            let fc = FuncCall {
                funcname: "ReadFile".into(),
                buffer: Some(BASE64_STANDARD.encode(&buf[..]).into()),
                handle: raw_handle,
                filename,
            };
            dbg.logln(serde_json::to_string(&fc).unwrap());
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn trace_write(raw_client: *mut c_void, args: PCSTR) -> HRESULT {
    wrap(raw_client, args, |dbg, args| -> Result<()> {
        dlogln!(dbg, "Inside 'trace_write' {args:?}");
        let raw_handle = dbg.get_arg(0)?;
        let buffer_addr = dbg.get_arg(1)?;
        let buffer_size = dbg.get_arg(2)? as usize;
        let mut buf = vec![0u8; buffer_size];
        dbg.read_memory_exact(buffer_addr, &mut buf[..])?;

        let filename = get_handles()
            .read()
            .ok()
            .and_then(|h| h.get(&raw_handle).cloned())
            .map(Cow::Owned);
        let fc = FuncCall {
            funcname: "WriteFile".into(),
            buffer: Some(BASE64_STANDARD.encode(&buf[..]).into()),
            handle: raw_handle,
            filename,
        };
        dbg.logln(serde_json::to_string(&fc).unwrap());
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn trace_close(raw_client: *mut c_void, args: PCSTR) -> HRESULT {
    wrap(raw_client, args, |dbg, args| -> Result<()> {
        dlogln!(dbg, "Inside 'trace_close' {args:?}");
        let raw_handle = dbg.get_arg(0)?;

        let filename = get_handles()
            .write()
            .ok()
            .and_then(|mut h| h.remove(&raw_handle))
            .map(Cow::Owned);
        let fc = FuncCall {
            funcname: "CloseHandle".into(),
            buffer: None,
            handle: raw_handle,
            filename,
        };
        dbg.logln(serde_json::to_string(&fc).unwrap());

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn wintrace(raw_client: *mut c_void, args: PCSTR) -> HRESULT {
    wrap(raw_client, args, |dbg, _| {
        dlogln!(dbg, "Inside 'wintrace'");

        dbg.add_breakpoint("kernel32!CreateFileW", Some("!trace_createfilew"))?;
        dbg.add_breakpoint("kernel32!ReadFile", Some("!trace_read"))?;
        dbg.add_breakpoint("kernel32!WriteFile", Some("!trace_write"))?;
        dbg.add_breakpoint("kernel32!CloseHandle", Some("!trace_close"))?;

        Ok(())
    })
}

/// The DebugExtensionInitialize callback function is called by the engine after
/// loading a DbgEng extension DLL. https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nc-dbgeng-pdebug_extension_initialize
#[no_mangle]
extern "C" fn DebugExtensionInitialize(_version: *mut u32, _flags: *mut u32) -> HRESULT {
    S_OK
}

#[no_mangle]
extern "C" fn DebugExtensionUninitialize() {}
