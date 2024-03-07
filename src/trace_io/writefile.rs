use crate::{debugger::Debugger, trace_call};
use base64::prelude::{Engine, BASE64_STANDARD};
use std::{
    borrow::Cow,
    collections::HashMap,
    ptr,
    sync::{atomic::AtomicPtr, Mutex},
};
use windows::core::Result;

pub(super) static WRITEFILE_ARGS: AtomicPtr<Mutex<HashMap<usize, WriteFileArgs>>> =
    AtomicPtr::new(ptr::null_mut());

pub(super) struct WriteFileArgs {
    handle: usize,
    buffer_addr: usize,
    buffer_size: usize,
    buffer_len_addr: usize,
}

fn register_args(dbg: &Debugger, arg: WriteFileArgs) -> Result<()> {
    super::register_args(dbg, &WRITEFILE_ARGS, arg)
}

fn get_args(dbg: &Debugger) -> Result<Option<WriteFileArgs>> {
    super::get_args(dbg, &WRITEFILE_ARGS)
}

fn filter_writefile(
    dbg: &Debugger,
    handle: usize,
    buffer_addr: usize,
    buffer_size: usize,
    buffer_len_addr: usize,
) -> Result<bool> {
    if !super::is_handle_registered(handle)? {
        return Ok(false);
    }
    let rf = WriteFileArgs {
        handle,
        buffer_addr,
        buffer_size,
        buffer_len_addr,
    };
    register_args(dbg, rf)?;
    Ok(true)
}

fn trace_writefile_inner(dbg: &Debugger) -> Result<()> {
    let Some(WriteFileArgs {
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
        log::debug!("write failed on handle {handle:x}");
        return Ok(());
    }
    let filename = super::get_registered_handle(handle)?.map(Cow::Owned);

    if buffer_len_addr != 0 {
        buffer_size = unsafe { dbg.derefence::<u32>(buffer_len_addr) }? as usize;
    }
    let mut buf = vec![0u8; buffer_size];
    dbg.read_memory_exact(buffer_addr, &mut buf[..])?;

    let fc = super::FuncCall {
        funcname: "WriteFile".into(),
        buffer: Some(BASE64_STANDARD.encode(&buf[..]).into()),
        handle,
        filename,
    };
    crate::save_call(&fc);
    Ok(())
}

trace_call!(RET trace_writefile, dbg, { filter_writefile(dbg, handle, buffer_addr, buffer_size, buffer_len_addr) }, WriteFile(handle, buffer_addr, buffer_size, buffer_len_addr) {{
    trace_writefile_inner(dbg)
}});
