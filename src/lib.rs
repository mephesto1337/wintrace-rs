use std::ffi::c_void;
use windows::{
    core::{HRESULT, PCSTR},
    Win32::{
        Foundation::S_OK,
        System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
    },
};

#[macro_export]
macro_rules! dlogln {
    ($dbg:ident, $($arg:tt)*) => {{
        $dbg.logln(format!($($arg)*))
    }};
}

pub mod debugger;
pub mod helpers;
pub mod trace_io;

use helpers::wrap;

#[no_mangle]
#[export_name = "_DllMain@12"]
pub extern "C" fn DllMain(_hinst: isize, reason: u32, _reserved: isize) -> i32 {
    match reason {
        DLL_PROCESS_ATTACH => {
            trace_io::init(true);
        }
        DLL_PROCESS_DETACH => {
            trace_io::deinit(true);
        }
        _ => {}
    }
    1
}

#[no_mangle]
pub extern "C" fn wintrace(raw_client: *mut c_void, args: PCSTR) -> HRESULT {
    wrap(raw_client, args, "wintrace", |dbg, _| {
        dbg.add_breakpoint("kernel32!CreateFileA", Some("!trace_createfilea"))?;
        dbg.add_breakpoint("kernel32!CreateFileW", Some("!trace_createfilew"))?;
        dbg.add_breakpoint("kernel32!ReadFile", Some("!trace_readfile"))?;
        dbg.add_breakpoint("kernel32!WriteFile", Some("!trace_writefile"))?;
        dbg.add_breakpoint("kernel32!CloseHandle", Some("!trace_closehandle"))?;

        Ok(())
    })
}

/// The DebugExtensionInitialize callback function is called by the engine after
/// loading a DbgEng extension DLL. https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nc-dbgeng-pdebug_extension_initialize
#[no_mangle]
extern "C" fn DebugExtensionInitialize(_version: *mut u32, _flags: *mut u32) -> HRESULT {
    S_OK
}

#[no_mangle]
extern "C" fn DebugExtensionUninitialize() {}
