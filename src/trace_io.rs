use crate::debugger::Debugger;
use serde::Serialize;
use std::{
    borrow::Cow,
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

pub mod closehandle;
pub mod createfile;
pub mod readfile;
pub mod writefile;

pub mod createfilemapping;
pub mod mapviewoffile;

fn register_args<T>(
    dbg: &Debugger,
    at: &AtomicPtr<Mutex<HashMap<usize, T>>>,
    arg: T,
) -> Result<()> {
    let tid = dbg.get_thread_id()?;

    let mut args = unsafe { &*at.load(Ordering::Relaxed) }
        .lock()
        .map_err(|_| Error::new(E_UNEXPECTED, "Could not lock ARGS"))?;
    args.insert(tid, arg);
    Ok(())
}

fn get_args<T>(dbg: &Debugger, at: &AtomicPtr<Mutex<HashMap<usize, T>>>) -> Result<Option<T>> {
    let tid = dbg.get_thread_id()?;

    let mut readfile_args = unsafe { &*at.load(Ordering::Relaxed) }
        .lock()
        .map_err(|_| Error::new(E_UNEXPECTED, "Could not lock ARGS"))?;
    let arg = readfile_args.remove(&tid);
    Ok(arg)
}

macro_rules! initialize_with {
    ($what:expr, $with:expr) => {
        let val = $with;
        log::debug!(
            "Initialized {} with {}/{val:?}",
            stringify!($what),
            stringify!($with),
        );
        let val = Box::into_raw(Box::new(val));
        let old_val = $what.swap(val, Ordering::Relaxed);
        if !old_val.is_null() {
            let _ = unsafe { Box::from_raw(old_val) };
        }
    };
}

fn deinitialize_at<T>(at: &AtomicPtr<T>) {
    let old_val = at.swap(ptr::null_mut(), Ordering::Relaxed);
    if !old_val.is_null() {
        let _ = unsafe { Box::from_raw(old_val) };
    }
}

pub(super) fn deinit() {
    deinitialize_at(&readfile::READFILE_ARGS);
    deinitialize_at(&createfile::CREATEFILE_ARGS);
    deinitialize_at(&writefile::WRITEFILE_ARGS);
}

pub(super) fn init() {
    initialize_with!(&createfile::CREATEFILE_ARGS, Default::default());
    initialize_with!(&readfile::READFILE_ARGS, Default::default());
    initialize_with!(&writefile::WRITEFILE_ARGS, Default::default());
}

#[derive(Debug, Serialize, Default)]
struct FuncCall<'a> {
    pub exename: Cow<'a, str>,
    pub funcname: Cow<'a, str>,
    pub handle: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer: Option<Cow<'a, str>>,
}
