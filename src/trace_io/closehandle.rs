use crate::{debugger::Debugger, get_args, trace_call};
use std::borrow::Cow;
use windows::core::Result;

fn trace_closehandle_inner(_dbg: &Debugger, handle: usize) -> Result<()> {
    let filename = super::unregister_handle(handle)?.map(Cow::Owned);

    if filename.is_none() {
        // We were not tracking this handle
        return Ok(());
    }

    let fc = super::FuncCall {
        funcname: "CloseHandle".into(),
        handle,
        filename,
        ..Default::default()
    };
    crate::save_call(&fc);
    Ok(())
}

trace_call!(trace_closehandle, dbg, CloseHandle(handle) {{
    trace_closehandle_inner(dbg, handle)
}});
