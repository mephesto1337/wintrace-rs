use crate::{debugger::Debugger, helpers::wrap};
use serde::Serialize;
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    ffi::c_void,
    ptr,
    sync::{
        atomic::{AtomicPtr, Ordering},
        Mutex, RwLock,
    },
};
use windows::{
    core::{Error, Result, HRESULT, PCSTR},
    Win32::Foundation::E_UNEXPECTED,
};

pub mod closehandle;
pub mod createfile;
pub mod readfile;
pub mod writefile;

static HANDLES: AtomicPtr<RwLock<BTreeMap<usize, String>>> = AtomicPtr::new(ptr::null_mut());

fn register_args<T>(
    dbg: &Debugger,
    at: &AtomicPtr<Mutex<HashMap<usize, T>>>,
    arg: T,
) -> Result<()> {
    let tid = dbg.get_thread_id()?;

    let mut args = unsafe { &*at.load(Ordering::Relaxed) }
        .lock()
        .map_err(|_| Error::new(E_UNEXPECTED, "Could not lock ARGS"))?;
    args.insert(tid, arg);
    Ok(())
}

fn get_args<T>(dbg: &Debugger, at: &AtomicPtr<Mutex<HashMap<usize, T>>>) -> Result<Option<T>> {
    let tid = dbg.get_thread_id()?;

    let mut readfile_args = unsafe { &*at.load(Ordering::Relaxed) }
        .lock()
        .map_err(|_| Error::new(E_UNEXPECTED, "Could not lock ARGS"))?;
    let arg = readfile_args.remove(&tid);
    Ok(arg)
}

macro_rules! initialize_with {
    ($what:expr, $with:expr) => {
        let val = $with;
        log::debug!(
            "Initialized {} with {}/{val:?}",
            stringify!($what),
            stringify!($with),
        );
        let val = Box::into_raw(Box::new(val));
        let old_val = $what.swap(val, Ordering::Relaxed);
        if !old_val.is_null() {
            let _ = unsafe { Box::from_raw(old_val) };
        }
    };
}

fn deinitialize_at<T>(at: &AtomicPtr<T>) {
    let old_val = at.swap(ptr::null_mut(), Ordering::Relaxed);
    if !old_val.is_null() {
        let _ = unsafe { Box::from_raw(old_val) };
    }
}

pub(super) fn deinit() {
    deinitialize_at(&HANDLES);
    deinitialize_at(&readfile::READFILE_ARGS);
    deinitialize_at(&createfile::CREATEFILE_ARGS);
    deinitialize_at(&writefile::WRITEFILE_ARGS);
}

pub(super) fn init() {
    initialize_with!(&HANDLES, Default::default());
    initialize_with!(&createfile::CREATEFILE_ARGS, Default::default());
    initialize_with!(&readfile::READFILE_ARGS, Default::default());
    initialize_with!(&writefile::WRITEFILE_ARGS, Default::default());
}

fn get_handles() -> &'static RwLock<BTreeMap<usize, String>> {
    let handle = HANDLES.load(Ordering::Relaxed);
    assert_ne!(handle, ptr::null_mut(), "HANDLE has not been initialized");

    unsafe { &*handle }
}

fn unregister_handle(handle: usize) -> Result<Option<String>> {
    let mut handles = get_handles().write().map_err(|_| {
        ::windows::core::Error::new(
            ::windows::Win32::Foundation::E_UNEXPECTED,
            "Could not lock handles for writing",
        )
    })?;
    let ret = handles.remove(&handle);
    if let Some(filename) = ret.as_ref() {
        log::info!("Unregister handle {handle:x} for {filename:?}");
    }
    Ok(ret)
}

fn register_handle(handle: usize, filename: String) -> Result<()> {
    let mut handles = get_handles().write().map_err(|_| {
        ::windows::core::Error::new(
            ::windows::Win32::Foundation::E_UNEXPECTED,
            "Could not lock handles for writing",
        )
    })?;
    log::info!("Register handle {handle:x} for {filename:?}");
    handles.insert(handle, filename);
    Ok(())
}

fn get_registered_handle(handle: usize) -> Result<Option<String>> {
    let handles = get_handles().read().map_err(|_| {
        ::windows::core::Error::new(
            ::windows::Win32::Foundation::E_UNEXPECTED,
            "Could not lock handles for reading",
        )
    })?;
    Ok(handles.get(&handle).cloned())
}

fn is_handle_registered(handle: usize) -> Result<bool> {
    let handles = get_handles().read().map_err(|_| {
        ::windows::core::Error::new(
            ::windows::Win32::Foundation::E_UNEXPECTED,
            "Could not lock handles for reading",
        )
    })?;
    Ok(handles.contains_key(&handle))
}

#[no_mangle]
pub extern "C" fn register_handles(raw_client: *mut c_void, args: PCSTR) -> HRESULT {
    wrap(raw_client, args, "register_handles", |dbg, args| {
        if args.is_empty() {
            if let Ok(handles) = get_handles().read() {
                for (handle, filename) in handles.iter() {
                    log::info!("{handle:x}={filename}");
                    let _ = dbg.run(format!(".echo {handle:x}={filename}"));
                }
            } else {
                log::error!("Could not lock handles for reading");
            }
            return Ok(());
        }
        for handle_label in args.split_whitespace() {
            let (handle, label) = handle_label.split_once('=').unwrap_or((handle_label, ""));
            let Ok(handle) = usize::from_str_radix(handle, 16) else {
                log::warn!("Could not parse hex number {handle:?}");
                continue;
            };
            register_handle(handle, label.into())?;
        }
        Ok(())
    })
}

#[derive(Debug, Serialize, Default)]
struct FuncCall<'a> {
    pub exename: Cow<'a, str>,
    pub funcname: Cow<'a, str>,
    pub handle: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer: Option<Cow<'a, str>>,
}
