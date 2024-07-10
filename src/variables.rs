use crate::helpers::wrap;
use std::{
    collections::BTreeMap,
    ffi::c_void,
    fmt::Debug,
    ptr,
    sync::{
        atomic::{AtomicPtr, Ordering},
        RwLock,
    },
};
use windows::core::{Result, HRESULT, PCSTR};

trait HandleType {
    type Item: 'static + Debug + Clone;

    fn index() -> usize;
}

macro_rules! defined_handle_types {
    ($name:ident $($tt:tt)*) => {
        defined_handle_types!("", __inner, 0, $name $($tt)*);
    };
    ($x:literal, __inner_single, $counter:expr, $name:ident, $item:ty) => {
        #[derive(Debug)]
        pub enum $name {}

        impl $name {
            pub fn register(handle: usize, tag: String) -> Result<()> {
                register_handle::<Self>(handle, tag)
            }
            pub fn unregister(handle: usize) -> Result<Option<$item>> {
                unregister_handle::<Self>(handle)
            }
            pub fn get_tag(handle: usize) -> Result<Option<$item>> {
                get_registered_handle::<Self>(handle)
            }
            pub fn is_registered(handle: usize) -> Result<bool> {
                is_handle_registered::<Self>(handle)
            }
        }

        impl HandleType for $name {
            type Item = $item;
            fn index() -> usize { $counter }
        }
    };
    ($x:literal, __inner, $counter:expr, $name:ident ) => {
        defined_handle_types!($x, __inner_single, $counter, $name, String);
        pub const MAX_HANDLES_TYPE: usize = $counter + 1;
    };
    ($x:literal, __inner, $counter:expr, $name:ident ( $item:ty) ) => {
        defined_handle_types!($x, __inner_single, $counter, $name, $item);
        pub const MAX_HANDLES_TYPE: usize = $counter + 1;
    };
    ($x:literal, __inner, $counter:expr, $name:ident ( $item:ty ), $($names:ident),*) => {
        defined_handle_types!($x, __inner_single, $counter, $name, $item);
        defined_handle_types!($x, __inner, $counter + 1, $($names),*);
    };
    ($x:literal, __inner, $counter:expr, $name:ident, $($names:ident),*) => {
        defined_handle_types!($x, __inner_single, $counter, $name, String);
        defined_handle_types!($x, __inner, $counter + 1, $($names),*);
    };
}

defined_handle_types!(HandleFile, HandleMap);

type HandlePtr = AtomicPtr<RwLock<BTreeMap<usize, ()>>>;
#[allow(clippy::declare_interior_mutable_const)]
const INIT_HANDLE_PTR: HandlePtr = AtomicPtr::new(ptr::null_mut());

static HANDLES: [HandlePtr; MAX_HANDLES_TYPE] = [INIT_HANDLE_PTR; MAX_HANDLES_TYPE];

fn get_handles<T: HandleType>() -> &'static RwLock<BTreeMap<usize, T::Item>> {
    let handle = HANDLES[T::index()].load(Ordering::Relaxed).cast();
    assert_ne!(handle, ptr::null_mut(), "HANDLE has not been initialized");

    unsafe { &*handle }
}

fn unregister_handle<T: HandleType>(handle: usize) -> Result<Option<T::Item>> {
    let mut handles = get_handles::<T>().write().map_err(|_| {
        ::windows::core::Error::new(
            ::windows::Win32::Foundation::E_UNEXPECTED,
            "Could not lock handles for writing",
        )
    })?;
    let ret = handles.remove(&handle);
    if let Some(tag) = ret.as_ref() {
        log::info!("Unregister handle {handle:x} for {tag:?}");
    }
    Ok(ret)
}

fn register_handle<T: HandleType>(handle: usize, tag: T::Item) -> Result<()> {
    let mut handles = get_handles::<T>().write().map_err(|_| {
        ::windows::core::Error::new(
            ::windows::Win32::Foundation::E_UNEXPECTED,
            "Could not lock handles for writing",
        )
    })?;
    log::info!("Register handle {handle:x} for {tag:?}");
    handles.insert(handle, tag);
    Ok(())
}

fn get_registered_handle<T: HandleType>(handle: usize) -> Result<Option<T::Item>> {
    let handles = get_handles::<T>().read().map_err(|_| {
        ::windows::core::Error::new(
            ::windows::Win32::Foundation::E_UNEXPECTED,
            "Could not lock handles for reading",
        )
    })?;
    Ok(handles.get(&handle).cloned())
}

fn is_handle_registered<T: HandleType>(handle: usize) -> Result<bool> {
    let handles = get_handles::<T>().read().map_err(|_| {
        ::windows::core::Error::new(
            ::windows::Win32::Foundation::E_UNEXPECTED,
            "Could not lock handles for reading",
        )
    })?;
    Ok(handles.contains_key(&handle))
}

#[no_mangle]
pub extern "C" fn register_handles(raw_client: *mut c_void, args: PCSTR) -> HRESULT {
    wrap(raw_client, args, "register_handles", |dbg, args| {
        if args.is_empty() {
            if let Ok(handles) = get_handles::<HandleFile>().read() {
                for (handle, filename) in handles.iter() {
                    log::info!("{handle:x}={filename}");
                    let _ = dbg.run(format!(".echo {handle:x}={filename}"));
                }
            } else {
                log::error!("Could not lock handles for reading");
            }
            return Ok(());
        }
        for handle_label in args.split_whitespace() {
            let (handle, label) = handle_label.split_once('=').unwrap_or((handle_label, ""));
            let Ok(handle) = usize::from_str_radix(handle, 16) else {
                log::warn!("Could not parse hex number {handle:?}");
                continue;
            };
            register_handle::<HandleFile>(handle, label.into())?;
        }
        Ok(())
    })
}
