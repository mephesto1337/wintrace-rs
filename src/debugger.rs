use std::{
    ffi::OsString,
    mem::{size_of, MaybeUninit},
    os::windows::ffi::OsStringExt,
};

use windows::{
    core::{IUnknown, Interface, Result, HRESULT, PCSTR},
    Win32::{
        Foundation::ERROR_DS_DECODING_ERROR,
        System::{
            Diagnostics::Debug::Extensions::{
                IDebugBreakpoint, IDebugControl3, IDebugDataSpaces4, IDebugRegisters,
                IDebugSymbols, DEBUG_ANY_ID, DEBUG_BREAKPOINT_CODE, DEBUG_BREAKPOINT_ENABLED,
                DEBUG_BREAKPOINT_ONE_SHOT, DEBUG_EXECUTE_ECHO, DEBUG_OUTCTL_ALL_CLIENTS,
                DEBUG_OUTPUT_NORMAL,
            },
            SystemInformation::{
                IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM,
                IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_IA64,
            },
        },
    },
};

macro_rules! to_cstring {
    ($into_vec:expr) => {
        ::std::ffi::CString::new($into_vec).map_err(|_| {
            ::windows::core::Error::new(
                ::windows::Win32::Foundation::E_INVALIDARG,
                "Nul byte in string",
            )
        })
    };
}

pub struct Debugger {
    control: IDebugControl3,
    registers: IDebugRegisters,
    dataspaces: IDebugDataSpaces4,
    _symbols: IDebugSymbols,
    ptype: ProcessorType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessorType {
    I386,
    Arm,
    IA64,
    Amd64,
    Efi,
    Unknown(u32),
}

impl ProcessorType {
    fn from_u32(val: u32) -> Self {
        match IMAGE_FILE_MACHINE(val as u16) {
            IMAGE_FILE_MACHINE_ARM => Self::Arm,
            IMAGE_FILE_MACHINE_I386 => Self::I386,
            IMAGE_FILE_MACHINE_AMD64 => Self::Amd64,
            IMAGE_FILE_MACHINE_IA64 => Self::IA64,
            _ => Self::Unknown(val),
        }
    }
}

pub struct Breakpoint(IDebugBreakpoint);

impl Breakpoint {
    pub fn id(&self) -> Result<u32> {
        unsafe { self.0.GetId() }
    }

    pub fn oneshot(&self) -> Result<()> {
        unsafe { self.0.AddFlags(DEBUG_BREAKPOINT_ONE_SHOT) }
    }
}

trait Number: Eq + Copy + Default + std::fmt::Display {
    fn zero() -> Self;
}
macro_rules! impl_numbers {
    ($type:ty) => {
        impl Number for $type {
            fn zero() -> Self {
                0
            }
        }
    };
}
impl_numbers!(u8);
impl_numbers!(u16);
impl_numbers!(u32);
impl_numbers!(usize);
impl_numbers!(i8);
impl_numbers!(i16);
impl_numbers!(i32);
impl_numbers!(i64);

fn get_processor_type(control: &IDebugControl3) -> Result<ProcessorType> {
    let ptype = unsafe { control.GetActualProcessorType() }?;
    Ok(ProcessorType::from_u32(ptype))
}

impl Debugger {
    pub fn new(unk: &IUnknown) -> Result<Self> {
        let control = unk.cast()?;
        let registers = unk.cast()?;
        let dataspaces = unk.cast()?;
        let _symbols = unk.cast()?;
        let ptype = get_processor_type(&control)?;

        Ok(Self {
            control,
            registers,
            dataspaces,
            _symbols,
            ptype,
        })
    }

    pub fn get_processor_type(&self) -> ProcessorType {
        self.ptype
    }

    pub fn get_register_value(&self, reg: impl Into<Vec<u8>>) -> Result<usize> {
        let c_name = to_cstring!(reg)?;
        let index = unsafe {
            self.registers
                .GetIndexByName(PCSTR::from_raw(c_name.as_ptr().cast()))
        }?;

        let value = unsafe {
            let mut value = MaybeUninit::uninit();
            self.registers.GetValue(index, value.as_mut_ptr())?;
            value.assume_init()
        };

        #[cfg(target_pointer_width = "32")]
        {
            Ok(unsafe { value.Anonymous.I32 } as usize)
        }

        #[cfg(target_pointer_width = "64")]
        {
            Ok(unsafe { value.Anonymous.Anonymous.I64 } as usize)
        }
    }

    pub fn get_stack(&self) -> Result<usize> {
        let addr = unsafe { self.registers.GetStackOffset() }?;
        Ok(addr as usize)
    }

    pub fn read_memory(&self, va: usize, buf: &mut [u8]) -> Result<usize> {
        let buflen: u32 = buf.len().try_into().unwrap_or(u32::MAX);
        let mut bytes_read = MaybeUninit::uninit();
        unsafe {
            self.dataspaces.ReadVirtual(
                va as u64,
                buf.as_mut_ptr().cast(),
                buflen,
                Some(bytes_read.as_mut_ptr()),
            )
        }?;

        let bytes_read = unsafe { bytes_read.assume_init() } as usize;
        log::trace!("Read {bytes_read} bytes from VA 0x{va:x}");
        Ok(bytes_read)
    }

    pub fn read_memory_exact(&self, mut va: usize, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            let n = self.read_memory(va, buf)?;
            va += n;
            buf = &mut buf[n..];
        }
        Ok(())
    }

    /// # Safety
    /// T must be valid for any raw content, for instance POD.
    pub unsafe fn read_into<T: Sized + std::fmt::Debug>(
        &self,
        va: usize,
        val: &mut T,
    ) -> Result<()> {
        let ptr = val as *mut T;
        let buf = unsafe { std::slice::from_raw_parts_mut(ptr.cast(), size_of::<T>()) };
        self.read_memory_exact(va, buf)?;
        log::trace!("Read {val:?} from VA 0x{va:x}");
        Ok(())
    }

    pub fn get_ip(&self) -> Result<usize> {
        let ip = unsafe { self.registers.GetInstructionOffset() }?;
        Ok(ip as usize)
    }

    pub fn get_next_ip(&self) -> Result<usize> {
        let ip = self.get_ip()?;
        let nxt_ip = unsafe { self.control.GetNearInstruction(ip as u64, 1) }?;
        Ok(nxt_ip as usize)
    }

    /// # Safety
    /// T must be valid for any raw content, for instance POD.
    pub unsafe fn derefence<T: Sized + std::fmt::Debug>(&self, va: usize) -> Result<T> {
        let mut val = MaybeUninit::<T>::uninit();
        let buf =
            unsafe { std::slice::from_raw_parts_mut(val.as_mut_ptr().cast(), size_of::<T>()) };
        self.read_memory_exact(va, buf)?;
        let val = unsafe { val.assume_init() };
        log::trace!("Derefence 0x{va:x}: {:?}", val);
        Ok(val)
    }

    fn read_string_char<T: Number>(&self, va: usize) -> Result<Vec<T>> {
        let mut res = Vec::with_capacity(256);
        loop {
            let len = res.len();
            let buf: &mut [u8] = unsafe { std::mem::transmute(res.spare_capacity_mut()) };
            let n = self.read_memory(va, buf)?;
            unsafe { res.set_len(len + n) };
            if n == 0 {
                return Ok(res);
            }
            if let Some(null_idx) = res[len..]
                .iter()
                .enumerate()
                .find_map(|(i, b)| (*b == T::zero()).then_some(i))
            {
                unsafe { res.set_len(len + null_idx) };
                return Ok(res);
            }
            res.reserve(256);
        }
    }

    pub fn read_cstring(&self, va: usize) -> Result<String> {
        let buf = self.read_string_char::<u8>(va)?;
        String::from_utf8(buf).map_err(|_| {
            windows::core::Error::new(
                HRESULT::from_win32(ERROR_DS_DECODING_ERROR.0),
                "Bad UTF-8 sequence",
            )
        })
    }

    pub fn read_wstring(&self, va: usize) -> Result<String> {
        let buf = self.read_string_char::<u16>(va)?;
        let s = OsString::from_wide(&buf[..]);
        s.into_string().map_err(|_| {
            windows::core::Error::new(
                HRESULT::from_win32(ERROR_DS_DECODING_ERROR.0),
                "Bad UTF-16 sequence",
            )
        })
    }

    fn get_arg_i386(&self, idx: usize) -> Result<usize> {
        let esp = self.get_stack()?;
        let offset = (idx + 1) * 4;
        let reg = unsafe { self.derefence(esp + offset) }?;
        Ok(reg)
    }

    fn get_arg_amd64(&self, idx: usize) -> Result<usize> {
        match idx {
            0 => self.get_register_value("rcx"),
            1 => self.get_register_value("rdx"),
            2 => self.get_register_value("r8"),
            3 => self.get_register_value("r9"),
            _ => {
                let rsp = self.get_stack()?;
                let offset = (idx - 3) * 8;
                let reg = unsafe { self.derefence(rsp + offset) }?;
                Ok(reg)
            }
        }
    }

    pub fn get_arg(&self, idx: usize) -> Result<usize> {
        match self.get_processor_type() {
            ProcessorType::I386 => self.get_arg_i386(idx),
            ProcessorType::Amd64 => self.get_arg_amd64(idx),
            _ => Err(windows::core::Error::new(
                windows::Win32::Foundation::E_NOTIMPL,
                "Only i386 and amd64 are handled",
            )),
        }
    }

    pub fn get_return_value(&self) -> Result<usize> {
        match self.get_processor_type() {
            ProcessorType::I386 => self.get_register_value("eax"),
            ProcessorType::Amd64 => self.get_register_value("rax"),
            _ => Err(windows::core::Error::new(
                windows::Win32::Foundation::E_NOTIMPL,
                "Only i386 and amd64 are handled",
            )),
        }
    }

    pub fn add_breakpoint(
        &self,
        symbol: impl Into<String>,
        command: Option<impl Into<String>>,
    ) -> Result<Breakpoint> {
        let c_symbol = to_cstring!(symbol.into())?;
        let bp = unsafe {
            self.control
                .AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID)
        }?;
        unsafe { bp.SetOffsetExpression(PCSTR::from_raw(c_symbol.as_ptr().cast())) }?;
        unsafe { bp.AddFlags(DEBUG_BREAKPOINT_ENABLED) }?;
        match command {
            Some(c) => {
                let mut command = c.into();
                command.push_str("; g");
                let cmd = to_cstring!(command.into_bytes())?;
                unsafe { bp.SetCommand(PCSTR::from_raw(cmd.as_ptr().cast())) }?;
            }
            None => {
                unsafe { bp.SetCommand(PCSTR::from_raw(b"g\0".as_ptr())) }?;
            }
        }

        log::debug!(
            "Added breakpoint #{id:?} on {symbol}",
            id = unsafe { bp.GetId() },
            symbol = c_symbol.to_str().unwrap(),
        );
        Ok(Breakpoint(bp))
    }

    pub fn remove_breakpoint(&self, bp: &Breakpoint) -> Result<()> {
        unsafe { self.control.RemoveBreakpoint(&bp.0) }
    }

    fn output(&self, mask: u32, buf: impl Into<Vec<u8>>) {
        let Ok(cstr) = std::ffi::CString::new(buf.into()) else {
            return;
        };
        let _ = unsafe {
            self.control
                .Output(mask, PCSTR::from_raw(cstr.as_ptr().cast()))
        };
    }

    pub fn log(&self, line: impl Into<Vec<u8>>) {
        self.output(DEBUG_OUTPUT_NORMAL, line)
    }

    pub fn logln(&self, line: impl Into<Vec<u8>>) {
        let mut buf = line.into();
        buf.push(b'\n');
        self.output(DEBUG_OUTPUT_NORMAL, buf)
    }

    pub fn run(&self, cmd: impl Into<Vec<u8>>) -> Result<()> {
        let c_cmd = to_cstring!(cmd)?;
        log::debug!("running {:?}", c_cmd.to_str().unwrap());
        unsafe {
            self.control.Execute(
                DEBUG_OUTCTL_ALL_CLIENTS,
                PCSTR::from_raw(c_cmd.as_ptr().cast()),
                DEBUG_EXECUTE_ECHO,
            )
        }
    }

    pub fn get_return_address(&self) -> Result<usize> {
        let ra = unsafe { self.control.GetReturnOffset() }?;
        Ok(ra as usize)
    }

    pub fn get_thread_id(&self) -> Result<usize> {
        self.get_register_value("$tid")
    }
}
