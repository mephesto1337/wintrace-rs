use crate::{debugger::Debugger, helpers};
use serde::Serialize;
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    ptr,
    sync::{
        atomic::{AtomicPtr, Ordering},
        Mutex, RwLock,
    },
};
use windows::{
    core::{Error, Result},
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

fn initialize_with<T, F>(at: &AtomicPtr<T>, f: F)
where
    F: FnOnce() -> T,
{
    let val = Box::leak(Box::new(f()));
    let old_val = at.swap(val, Ordering::Relaxed);
    if !old_val.is_null() {
        let _ = unsafe { Box::from_raw(old_val) };
    }
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
}

pub(super) fn init() {
    initialize_with(&HANDLES, Default::default);
    initialize_with(&createfile::CREATEFILE_ARGS, Default::default);
    initialize_with(&readfile::READFILE_ARGS, Default::default);
    let logfilename = helpers::expand_env(r"%USERPROFILE%\Desktop\wintrace.log");
    match std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&logfilename)
    {
        Ok(f) => {
            let _ = env_logger::builder()
                .filter_level(log::LevelFilter::Debug)
                .target(env_logger::Target::Pipe(Box::new(f) as Box<_>))
                .try_init();
        }
        Err(e) => {
            env_logger::init();
            log::warn!("Could not open log file ({logfilename}): {e}");
        }
    }
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
    Ok(handles.remove(&handle))
}

fn register_handle(handle: usize, filename: String) -> Result<()> {
    let mut handles = get_handles().write().map_err(|_| {
        ::windows::core::Error::new(
            ::windows::Win32::Foundation::E_UNEXPECTED,
            "Could not lock handles for writing",
        )
    })?;
    log::debug!("Before handles.insert");
    handles.insert(handle, filename);
    log::debug!("After  handles.insert");
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

#[derive(Debug, Serialize, Default)]
struct FuncCall<'a> {
    pub funcname: Cow<'a, str>,
    pub handle: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer: Option<Cow<'a, str>>,
}
