use crate::{debugger::Debugger, trace_call, variables::HandleFile};
use std::borrow::Cow;
use windows::core::Result;

fn trace_closehandle_inner(dbg: &Debugger, handle: usize) -> Result<()> {
    let filename = HandleFile::unregister(handle)?.map(Cow::Owned);

    if filename.is_none() {
        // We were not tracking this handle
        return Ok(());
    }

    let fc = super::FuncCall {
        exename: dbg.process(),
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
