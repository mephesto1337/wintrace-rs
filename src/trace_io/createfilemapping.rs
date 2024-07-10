use crate::{
    debugger::Debugger,
    trace_call,
    variables::{HandleFile, HandleMap},
};
use std::{
    collections::HashMap,
    ptr,
    sync::{
        atomic::{AtomicPtr, Ordering},
        Mutex,
    },
};
use windows::core::Result;

pub(super) static CREATEFILEMAPPING_ARGS: AtomicPtr<Mutex<HashMap<usize, CreateFileMappingArgs>>> =
    AtomicPtr::new(ptr::null_mut());

#[derive(Debug)]
pub(super) struct CreateFileMappingArgs {
    handle: usize,
}

fn register_args(dbg: &Debugger, arg: CreateFileMappingArgs) -> Result<()> {
    super::register_args(dbg, &CREATEFILEMAPPING_ARGS, arg)
}

fn get_args(dbg: &Debugger) -> Result<Option<CreateFileMappingArgs>> {
    super::get_args(dbg, &CREATEFILEMAPPING_ARGS)
}

fn filter_createfile(dbg: &Debugger, handle: usize) -> Result<bool> {
    let args = CreateFileMappingArgs { handle };
    register_args(dbg, args)?;
    Ok(true)
}

fn trace_createfile_inner(dbg: &Debugger, wide_string: bool) -> Result<()> {
    let Some(CreateFileMappingArgs {
        handle: file_handle,
    }) = get_args(dbg)?
    else {
        // We were not interested
        return Ok(());
    };
    let handle = dbg.get_return_value()?;
    if handle == u32::MAX as usize {
        // CreateFileMappingX failed
        return Ok(());
    }

    let funcname = if wide_string {
        "CreateFileMappingW"
    } else {
        "CreateFileMappingA"
    };

    let filename = HandleFile::get_tag(file_handle)?.unwrap_or_else(|| "???".into());
    HandleMap::register(handle, filename.clone())?;
    let fc = super::FuncCall {
        exename: dbg.process(),
        funcname: funcname.into(),
        handle,
        filename: Some(filename.into()),
        ..Default::default()
    };

    crate::save_call(&fc);

    Ok(())
}

trace_call!(RET trace_createfilew, dbg, { filter_createfile(dbg, handle) }, CreateFileMappingW(handle) {{
    trace_createfile_inner(dbg, true)
}});

trace_call!(RET trace_createfilea, dbg, { filter_createfile(dbg, handle) }, CreateFileMappingA(handle) {{
    trace_createfile_inner(dbg, false)
}});
