use crate::{debugger::Debugger, get_args, helpers, trace_call, trace_call_return};
use base64::{prelude::BASE64_STANDARD, Engine};
use serde::Serialize;
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    io::Write,
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

pub mod createfile;
pub mod readfile;

struct ReadFileArgs {
    buffer_addr: usize,
    buffer_size: usize,
    buffer_len_addr: usize,
}

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

pub(super) fn deinit(from_dllmain: bool) {
    let _ = from_dllmain;
    deinitialize_at(&HANDLES);
    deinitialize_at(&readfile::CREATEFILE_ARGS);
    deinitialize_at(&createfile::READFILE_ARGS);
}

pub(super) fn init(from_dllmain: bool) {
    initialize_with(&HANDLES, Default::default);
    initialize_with(&CREATEFILE_ARGS, Default::default);
    initialize_with(&READFILE_ARGS, Default::default);
    let logfilename = helpers::expand_env(r"%USERPROFILE%\Desktop\wintrace.log");
    match std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&logfilename)
    {
        Ok(f) => {
            let _ = env_logger::builder()
                .format(|buf, record| {
                    writeln!(
                        buf,
                        "{}:{} {} [{}] - {}",
                        record.file().unwrap_or("unknown"),
                        record.line().unwrap_or(0),
                        chrono::Local::now().format("%Y-%m-%dT%H:%M:%S"),
                        record.level(),
                        record.args()
                    )
                })
                .filter_level(log::LevelFilter::Debug)
                .target(env_logger::Target::Pipe(Box::new(f) as Box<_>))
                .try_init();
        }
        Err(e) => {
            env_logger::init();
            log::warn!("Could not open log file ({logfilename}): {e}");
        }
    }
    log::debug!("Called from DllMain: {from_dllmain}");
}

fn get_handles() -> &'static RwLock<BTreeMap<usize, String>> {
    let handle = HANDLES.load(Ordering::Relaxed);
    debug_assert_ne!(handle, ptr::null_mut(), "HANDLE has not been initialized");

    unsafe { &*handle }
}

fn unregister_handle(handle: usize, filename: String) -> Result<Option<String>> {
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

macro_rules! lock_handles {
    (read) => {
        lock_handles!(__priv read)
    };
    (write) => {
        lock_handles!(__priv write)
    };
    (__priv $method:ident) => {
        get_handles().$method().map_err(|_| {
            ::windows::core::Error::new(
                ::windows::Win32::Foundation::E_UNEXPECTED,
                concat!("Could not lock handles for ", stringify!($method)),
            )
        })
    };
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

fn filter_readwritefile(handle: usize) -> Result<bool> {
    Ok(lock_handles!(read)?.contains_key(&handle))
}

fn trace_writefile_inner(
    dbg: &Debugger,
    handle: usize,
    buffer_addr: usize,
    buffer_size: usize,
) -> Result<()> {
    let h = lock_handles!(read)?;
    let Some(filename) = h.get(&handle).cloned().map(Cow::Owned) else {
        // handle is not tracked
        return Ok(());
    };
    let mut buffer = vec![0u8; buffer_size as usize];
    dbg.read_memory_exact(buffer_addr, &mut buffer[..])?;
    let fc = FuncCall {
        funcname: "WriteFile".into(),
        handle,
        filename: Some(filename),
        buffer: Some(BASE64_STANDARD.encode(&buffer[..]).into()),
    };
    dbg.logln(serde_json::to_string(&fc).unwrap());
    Ok(())
}

fn trace_readfile_inner(
    dbg: &Debugger,
    handle: usize,
    buffer_addr: usize,
    mut buffer_size: usize,
    buffer_len_addr: usize,
) -> Result<()> {
    let success = dbg.get_return_value()?;
    if success == 0 {
        log::debug!("read failed on handle {handle:x}");
        return Ok(());
    }
    let h = lock_handles!(read)?;
    let Some(filename) = h.get(&handle).cloned().map(Cow::Owned) else {
        // handle is not tracked
        return Ok(());
    };

    if buffer_len_addr != 0 {
        buffer_size = unsafe { dbg.derefence::<u32>(buffer_len_addr) }? as usize;
    }
    let mut buf = vec![0u8; buffer_size as usize];
    dbg.read_memory_exact(buffer_addr, &mut buf[..])?;

    let fc = FuncCall {
        funcname: "ReadFile".into(),
        buffer: Some(BASE64_STANDARD.encode(&buf[..]).into()),
        handle,
        filename: Some(filename),
    };
    dbg.logln(serde_json::to_string(&fc).unwrap());
    Ok(())
}

fn trace_closehandle_inner(dbg: &Debugger, handle: usize) -> Result<()> {
    let mut h = lock_handles!(write)?;
    let Some(filename) = h.remove(&handle) else {
        return Ok(());
    };
    log::info!("Stop tracing handle {handle:x} ({filename:?})");
    let fc = FuncCall {
        funcname: "CloseHandle".into(),
        handle,
        filename: Some(filename.into()),
        ..Default::default()
    };
    dbg.logln(serde_json::to_string(&fc).unwrap());

    Ok(())
}

trace_call!(trace_writefile, dbg, { filter_readwritefile(handle) }, WriteFile(handle, buffer_addr, buffer_size) {{
    trace_writefile_inner(dbg, handle, buffer_addr, buffer_size)
}});

trace_call_return!(trace_readfile, dbg, { filter_readwritefile(handle) }, ReadFile(handle, buffer_addr, buffer_size, buffer_len_addr) {{
    trace_readfile_inner(dbg, handle, buffer_addr, buffer_size, buffer_len_addr)
}});

trace_call!(trace_closehandle, dbg, CloseHandle(handle) {{
    trace_closehandle_inner(dbg, handle)
}});
