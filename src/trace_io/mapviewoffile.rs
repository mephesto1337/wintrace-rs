use crate::{debugger::Debugger, trace_call, variables::HandleMap};
use base64::prelude::{Engine, BASE64_STANDARD};
use std::{
    borrow::Cow,
    collections::HashMap,
    ptr,
    sync::{atomic::AtomicPtr, Mutex},
};
use windows::core::Result;

// WINBASEAPI LPVOID WINAPI MapViewOfFile (
//      HANDLE hFileMappingObject,
//      DWORD dwDesiredAccess,
//      DWORD dwFileOffsetHigh,
//      DWORD dwFileOffsetLow,
//      SIZE_T dwNumberOfBytesToMap);
pub(super) static MAPVIEWOFFILE_ARGS: AtomicPtr<Mutex<HashMap<usize, MapViewOfFileArgs>>> =
    AtomicPtr::new(ptr::null_mut());

#[derive(Debug)]
pub(super) struct MapViewOfFileArgs {
    handle: usize,
    offset: usize,
    size: usize,
}

fn register_args(dbg: &Debugger, arg: MapViewOfFileArgs) -> Result<()> {
    super::register_args(dbg, &MAPVIEWOFFILE_ARGS, arg)
}

fn get_args(dbg: &Debugger) -> Result<Option<MapViewOfFileArgs>> {
    super::get_args(dbg, &MAPVIEWOFFILE_ARGS)
}

fn filter_mapviewoffile(
    dbg: &Debugger,
    handle: usize,
    _desired_access: usize,
    offset_high: usize,
    offset_low: usize,
    size: usize,
) -> Result<bool> {
    if !HandleMap::is_registered(handle)? {
        return Ok(false);
    }
    let offset = (offset_high as usize) << 32 | (offset_low as usize);
    let rf = MapViewOfFileArgs {
        handle,
        size,
        offset,
    };
    register_args(dbg, rf)?;
    Ok(true)
}

fn trace_mapviewoffile_inner(dbg: &Debugger) -> Result<()> {
    let Some(MapViewOfFileArgs {
        handle,
        offset,
        size,
    }) = get_args(dbg)?
    else {
        // We were not interested
        return Ok(());
    };
    let buffer_addr = dbg.get_return_value()?;
    if buffer_addr == 0 {
        log::debug!("MapViewOfFile failed on handle {handle:x}");
        return Ok(());
    }
    let filename = HandleMap::get_tag(handle)?.map(|f| Cow::Owned(format!("{f}+{offset:x}")));

    let mut buf = vec![0u8; size];
    dbg.read_memory_exact(buffer_addr, &mut buf[..])?;

    let fc = super::FuncCall {
        exename: dbg.process(),
        funcname: "MapViewOfFile".into(),
        buffer: Some(BASE64_STANDARD.encode(&buf[..]).into()),
        handle,
        filename,
    };
    crate::save_call(&fc);
    Ok(())
}

trace_call!(RET trace_mapviewoffile, dbg, { filter_mapviewoffile(dbg, map, desired_access, offset_high, offset_low, size) }, MapViewOfFile(map, desired_access, offset_high, offset_low, size) {{
    trace_mapviewoffile_inner(dbg)
}});
