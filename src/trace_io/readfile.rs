use crate::{debugger::Debugger, trace_call};
use base64::prelude::{Engine, BASE64_STANDARD};
use std::{
    borrow::Cow,
    collections::HashMap,
    ptr,
    sync::{atomic::AtomicPtr, Mutex},
};
use windows::core::Result;

pub(super) static READFILE_ARGS: AtomicPtr<Mutex<HashMap<usize, ReadFileArgs>>> =
    AtomicPtr::new(ptr::null_mut());

pub(super) struct ReadFileArgs {
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
    if !super::is_handle_registered(handle)? {
        return Ok(false);
    }
    let rf = ReadFileArgs {
        handle,
        buffer_addr,
        buffer_size,
        buffer_len_addr,
    };
    register_args(dbg, rf)?;
    Ok(true)
}

fn trace_readfile_inner(dbg: &Debugger) -> Result<()> {
    let Some(ReadFileArgs {
        handle,
        buffer_addr,
        mut buffer_size,
        buffer_len_addr,
    }) = get_args(dbg)?
    else {
        // We were not interested
        return Ok(());
    };
    let success = dbg.get_return_value()?;
    if success == 0 {
        log::debug!("read failed on handle {handle:x}");
        return Ok(());
    }
    let filename = super::get_registered_handle(handle)?.map(Cow::Owned);

    if buffer_len_addr != 0 {
        buffer_size = unsafe { dbg.derefence::<u32>(buffer_len_addr) }? as usize;
    }
    let mut buf = vec![0u8; buffer_size];
    dbg.read_memory_exact(buffer_addr, &mut buf[..])?;

    let fc = super::FuncCall {
        funcname: "ReadFile".into(),
        buffer: Some(BASE64_STANDARD.encode(&buf[..]).into()),
        handle,
        filename,
    };
    crate::save_call(&fc);
    Ok(())
}

trace_call!(RET trace_readfile, dbg, { filter_readfile(dbg, handle, buffer_addr, buffer_size, buffer_len_addr) }, ReadFile(handle, buffer_addr, buffer_size, buffer_len_addr) {{
    trace_readfile_inner(dbg)
}});
