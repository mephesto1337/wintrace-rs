use crate::{debugger::Debugger, get_args, trace_call};
use std::{
    collections::HashMap,
    ptr,
    sync::{atomic::AtomicPtr, Mutex},
};
use windows::core::Result;

pub(super) static CREATEFILE_ARGS: AtomicPtr<Mutex<HashMap<usize, CreateFileArgs>>> =
    AtomicPtr::new(ptr::null_mut());

pub(super) struct CreateFileArgs {
    filename: String,
}

fn register_args(dbg: &Debugger, arg: CreateFileArgs) -> Result<()> {
    super::register_args(dbg, &CREATEFILE_ARGS, arg)
}

fn get_args(dbg: &Debugger) -> Result<Option<CreateFileArgs>> {
    super::get_args(dbg, &CREATEFILE_ARGS)
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

    crate::save_call(&fc);

    Ok(())
}

trace_call!(RET trace_createfilew, dbg, { filter_createfile(dbg, filename_addr, true) }, CreateFileW(filename_addr) {{
    trace_createfile_inner(dbg, true)
}});

trace_call!(RET trace_createfilea, dbg, { filter_createfile(dbg, filename_addr, false) }, CreateFileA(filename_addr) {{
    trace_createfile_inner(dbg, false)
}});
