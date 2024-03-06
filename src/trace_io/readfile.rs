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

pub(super) static READFILE_ARGS: AtomicPtr<Mutex<HashMap<usize, ReadFileArgs>>> =
    AtomicPtr::new(ptr::null_mut());

struct ReadFileArgs {
    handle: usize,
    buffer_addr: usize,
    buffer_size: usize,
    buffer_len_addr: usize,
}

fn register_args(dbg: &Debugger, arg: ReadFileArgs) -> Result<()> {
    super::register_args(dbg, &READFILE_ARGS, arg)
}

fn get_args(dbg: &Debugger) -> Result<Option<ReadFileArgs>> {
    super::get_args(dbg, &READFILE_ARGS)
}

fn filter_readfile(
    dbg: &Debugger,
    handle: usize,
    buffer_addr: usize,
    buffer_size: usize,
    buffer_len_addr: usize,
) -> Result<bool> {
    log::debug!("In filter_readfile(handle={handle:x})");

    let interested = super::is_handle_registered(handle)?;
    if interested {
        let args = ReadFileArgs {
            handle,
            buffer_addr,
            buffer_size,
            buffer_len_addr,
        };
        register_args(dbg, args)?;
    }
    Ok(interested)
}

fn trace_readfile_inner(dbg: &Debugger, wide_string: bool) -> Result<()> {
    let Some(ReadFileArgs { filename }) = get_args(dbg)? else {
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

trace_call_return!(trace_readfilew, dbg, { filter_readfile(dbg, filename_addr, true) }, CreateFileW(filename_addr) {{
    trace_readfile_inner(dbg, true)
}});

trace_call_return!(trace_readfilea, dbg, { filter_readfile(dbg, filename_addr, false) }, CreateFileA(filename_addr) {{
    trace_readfile_inner(dbg, false)
}});
