use crate::{debugger::Debugger, get_args, trace_call};
use base64::prelude::{Engine, BASE64_STANDARD};
use std::borrow::Cow;
use windows::core::Result;

fn trace_writefile_inner(
    dbg: &Debugger,
    handle: usize,
    buffer_addr: usize,
    buffer_size: usize,
) -> Result<()> {
    if !super::is_handle_registered(handle)? {
        return Ok(());
    }
    let filename = super::get_registered_handle(handle)?.map(Cow::Owned);

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

trace_call!(trace_writefile, dbg, WriteFile(handle, buffer_addr, buffer_size) {{
    trace_writefile_inner(dbg, handle, buffer_addr, buffer_size)
}});
