use crate::debugger::Debugger;
use std::{env, ffi::c_void};
use windows::{
    core::{IUnknown, Interface, Result, HRESULT, PCSTR},
    Win32::Foundation::{E_ABORT, S_OK},
};

pub(super) fn expand_env(s: impl AsRef<str>) -> String {
    let mut s = s.as_ref();
    let mut expanded = String::with_capacity(s.len());

    fn find_env_var(s: &str) -> Option<(usize, usize)> {
        let start_env = s.find('%')?;
        let env_len = s[start_env + 1..].find('%')?;
        log::trace!(
            "Found env var placeholder: {start_env},{env_len}: {ph}",
            ph = &s[start_env..][..env_len + 2]
        );
        Some((start_env, env_len))
    }

    while let Some((start, len)) = find_env_var(s) {
        expanded.push_str(&s[..start]);
        let env_varname = &s[start + 1..][..len];
        if let Ok(var) = env::var(env_varname) {
            log::trace!("Replaced {env_varname} with {var}");
            expanded.push_str(&var);
        } else {
            log::trace!("Cannot find {env_varname}");
        }
        log::trace!("s <- {:?}", &s[start + len + 2..]);
        s = &s[start + len + 2..];
    }
    expanded.push_str(s);

    expanded
}

pub fn wrap<F>(raw_client: *mut c_void, args: PCSTR, funcname: &'static str, callback: F) -> HRESULT
where
    F: FnOnce(&Debugger, String) -> Result<()>,
{
    let args = unsafe { args.to_string() }.unwrap_or_default();
    let Some(client) = (unsafe { IUnknown::from_raw_borrowed(&raw_client) }) else {
        log::error!("Could not create IUnknown interface from {raw_client:x?}");
        return E_ABORT;
    };

    let dbg = match Debugger::new(client) {
        Ok(d) => d,
        Err(e) => {
            log::error!("Could not create Debugger from interface: {e}");
            return E_ABORT;
        }
    };

    if let Err(e) = callback(&dbg, args.clone()) {
        log::warn!(
            "Callback {funcname}({args:?}) failed: {msg}",
            msg = e.message()
        );
        e.code()
    } else {
        log::debug!("Callback !{funcname}({args:?}) succeded");
        S_OK
    }
}

/// `$filter` must store whatever necessary for `$exit_body`
#[macro_export]
macro_rules! trace_call {
    ($exportname:ident, $dbg:ident, $funcname:ident ( $($args:ident),*) { $body:expr }) => {
        trace_call!($exportname, $dbg, {{ Ok(true) }}, $funcname ( $($args),* ) { $body });
    };
    ($exportname:ident, $dbg:ident, { $filter:expr }, $funcname:ident ( $($args:ident),*) { $body:expr }) => {
        #[no_mangle]
        pub extern "C" fn $exportname(raw_client: *mut ::std::ffi::c_void, args: ::windows::core::PCSTR) -> ::windows::core::HRESULT {
            $crate::helpers::wrap( raw_client, args, stringify!($exportname), |$dbg, _args| -> Result<()> {
                use ::std::fmt::Write;

                trace_call!(__GET_ARGS $dbg, $($args),*);

                #[allow(unused_variables)]
                fn filter_func($dbg: &$crate::debugger::Debugger, $($args: usize),*) -> ::windows::core::Result<bool> {
                    $filter
                }
                fn body($dbg: &$crate::debugger::Debugger, $($args: usize),*) -> ::windows::core::Result<()> {
                    $body
                }

                let interested = filter_func($dbg, $($args),*);
                if log::log_enabled!(log::Level::Debug) {
                    let mut args = String::new();
                    $(write!(&mut args, " ,{}={:x}", stringify!($args), $args).unwrap();)*

                    log::debug!("{}({}): interested={:?}", stringify!($funcname), &args[2..], interested);
                }

                if let Ok(true) = interested {
                    if let Err(e) = body($dbg, $($args),*) {
                        log::warn!("callback for {} failed: {}", stringify!($funcname), e.message());
                    }
                }
                $dbg.go();
                Ok(())
            })
        }
    };
    (RET $exportname:ident, $dbg:ident, $funcname:ident ( $($args:ident),*) { $body:expr }) => {
        trace_call!(RET $exportname, $dbg, {{ Ok(true) }}, $funcname ( $($args),* ) { $body });
    };
    (RET $exportname:ident, $dbg:ident, { $filter:expr }, $funcname:ident ( $($args:ident),*) { $body:expr }) => {
        #[no_mangle]
        pub extern "C" fn $exportname(raw_client: *mut ::std::ffi::c_void, args: ::windows::core::PCSTR) -> ::windows::core::HRESULT {
            $crate::helpers::wrap( raw_client, args, stringify!($exportname), |$dbg, args| -> Result<()> {
                use ::std::fmt::Write;
                let ip = $dbg.get_ip()?;
                log::debug!("break on 0x{ip:x} for {} with {args:?}", stringify!($funcname));

                match args.as_str() {
                    "entry" => {
                        trace_call!(__GET_ARGS $dbg, $($args),*);

                        #[allow(unused_variables)]
                        fn filter_func($dbg: &$crate::debugger::Debugger, $($args: usize),*) -> ::windows::core::Result<bool> {
                            $filter
                        }
                        let interested = filter_func($dbg, $($args),*);

                        if log::log_enabled!(log::Level::Debug) {
                            let mut args = String::new();
                            $(write!(&mut args, ", {}={:x}", stringify!($args), $args).unwrap();)*

                            log::debug!("{}({}): interested={:?}", stringify!($funcname), &args[2..], interested);
                        }
                        if interested == Ok(true) {
                            let bp = $dbg.add_breakpoint("@$ra", Some(format!("!{} exit", stringify!($exportname))))?;
                            bp.oneshot()?;
                        }
                    },
                    "exit" => {
                        fn body($dbg: &$crate::debugger::Debugger) -> ::windows::core::Result<()> {
                            log::debug!("entring !{} body({})", stringify!($exportname), stringify!($body));
                            let res = $body;
                            log::debug!("exiting !{} body({res:?})", stringify!($exportname));
                            res
                        }
                        if let Err(e) = body($dbg) {
                            log::warn!("callback for {} failed: {}", stringify!($funcname), e.message());
                        }
                    }
                    _ => {
                        log::warn!("Unknown argument {args:?} for {}", stringify!($exportname));
                    }
                }
                $dbg.go();
                log::debug!("exiting {} {args:?}", stringify!($funcname));
                Ok(())
            })
        }
    };
    ( __GET_ARGS $dbg:ident, $($xs:ident),* ) => {
        trace_call!(__GET_ARGS PRIV $dbg, 0, $($xs),*)
    };
    ( __GET_ARGS PRIV $dbg:ident, $index:expr, $x:ident ) => {
        let $x = $dbg.get_arg($index)?;
    };
    ( __GET_ARGS PRIV $dbg:ident, $index:expr, $x:ident, $($xs:ident),* ) => {
        let $x = $dbg.get_arg($index)?;
        trace_call!(__GET_ARGS PRIV $dbg, $index + 1, $($xs),*)
    };
}
