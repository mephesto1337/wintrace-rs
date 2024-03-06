use crate::{debugger::Debugger, get_args, trace_call_return};
use std::{
    collections::HashMap,
    ptr,
    sync::{
        atomic::{AtomicPtr, Ordering},
        Mutex,
    },
};
use windows::{
    core::{Error, Result},
    Win32::Foundation::E_UNEXPECTED,
};

static CREATEFILE_ARGS: AtomicPtr<Mutex<HashMap<usize, CreateFileArgs>>> =
    AtomicPtr::new(ptr::null_mut());

struct CreateFileArgs {
    filename: String,
}

fn get_createfile_args() -> &'static Mutex<HashMap<usize, CreateFileArgs>> {
    let hm = CREATEFILE_ARGS.load(Ordering::Relaxed);
    debug_assert_ne!(hm, ptr::null_mut(), "HANDLE has not been initialized");
    unsafe { &*hm }
}

fn register_args(dbg: &Debugger, args: CreateFileArgs) -> Result<()> {
    let tid = dbg.get_thread_id()?;

    let mut createfile_args = get_createfile_args()
        .lock()
        .map_err(|_| Error::new(E_UNEXPECTED, "Could not lock CREATEFILE_ARGS"))?;
    createfile_args.insert(tid, args);
    Ok(())
}

fn get_args(dbg: &Debugger) -> Result<Option<CreateFileArgs>> {
    let tid = dbg.get_thread_id()?;

    let mut createfile_args = get_createfile_args()
        .lock()
        .map_err(|_| Error::new(E_UNEXPECTED, "Could not lock CREATEFILE_ARGS"))?;
    let args = createfile_args.remove(&tid);
    Ok(args)
}

fn filter_createfile(dbg: &Debugger, filename_addr: usize, wide_string: bool) -> Result<bool> {
    log::debug!("In filter_createfile(filename_addr={filename_addr:x})");
    let filename = if wide_string {
        dbg.read_wstring(filename_addr)?
    } else {
        dbg.read_cstring(filename_addr)?
    };
    let interested = filename == r"\\.\pipe\SpotlightHostConnectionService"
        || filename.starts_with(r"\\.\pipe\Avira");
    log::debug!(
        "CreateFile{}({filename:?}): {}interested",
        if wide_string { 'W' } else { 'A' },
        if interested { "" } else { "not " }
    );
    if interested {
        let args = CreateFileArgs { filename };
        register_args(dbg, args)?;
    }
    Ok(interested)
}

fn trace_createfile_inner(dbg: &Debugger, wide_string: bool) -> Result<()> {
    let Some(CreateFileArgs { filename }) = get_args(dbg)? else {
        // We were not interested
        return Ok(());
    };
    let handle = dbg.get_return_value()?;
    if handle == u32::MAX as usize {
        // CreateFileW failed
        return Ok(());
    }

    let funcname = if wide_string {
        "CreateFileW"
    } else {
        "CreateFileA"
    };

    super::register_handle(handle, filename.clone())?;
    log::info!("Tracing handle {handle:x} for file {filename:?}");
    let fc = super::FuncCall {
        funcname: funcname.into(),
        handle,
        filename: Some(filename.into()),
        ..Default::default()
    };
    dbg.logln(serde_json::to_string(&fc).unwrap());

    Ok(())
}

trace_call_return!(trace_createfilew, dbg, { filter_createfile(dbg, filename_addr, true) }, CreateFileW(filename_addr) {{
    trace_createfile_inner(dbg, true)
}});

trace_call_return!(trace_createfilea, dbg, { filter_createfile(dbg, filename_addr, false) }, CreateFileA(filename_addr) {{
    trace_createfile_inner(dbg, false)
}});
