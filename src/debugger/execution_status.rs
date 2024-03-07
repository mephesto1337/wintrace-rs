use windows::Win32::System::Diagnostics::Debug::Extensions::{
    DEBUG_STATUS_BREAK, DEBUG_STATUS_GO, DEBUG_STATUS_GO_HANDLED, DEBUG_STATUS_GO_NOT_HANDLED,
    DEBUG_STATUS_IGNORE_EVENT, DEBUG_STATUS_NO_CHANGE, DEBUG_STATUS_NO_DEBUGGEE,
    DEBUG_STATUS_OUT_OF_SYNC, DEBUG_STATUS_RESTART_REQUESTED, DEBUG_STATUS_STEP_BRANCH,
    DEBUG_STATUS_STEP_INTO, DEBUG_STATUS_STEP_OVER, DEBUG_STATUS_TIMEOUT, DEBUG_STATUS_WAIT_INPUT,
};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    NoDebuggee = DEBUG_STATUS_NO_DEBUGGEE,
    OutOfSync = DEBUG_STATUS_OUT_OF_SYNC,
    WaitInput = DEBUG_STATUS_WAIT_INPUT,
    Timeout = DEBUG_STATUS_TIMEOUT,
    Break = DEBUG_STATUS_BREAK,
    StepInto = DEBUG_STATUS_STEP_INTO,
    StepBranch = DEBUG_STATUS_STEP_BRANCH,
    StepOver = DEBUG_STATUS_STEP_OVER,
    GoNotHandled = DEBUG_STATUS_GO_NOT_HANDLED,
    GoHandled = DEBUG_STATUS_GO_HANDLED,
    Go = DEBUG_STATUS_GO,
    IgnoreEvent = DEBUG_STATUS_IGNORE_EVENT,
    RestartRequested = DEBUG_STATUS_RESTART_REQUESTED,
    NoChange = DEBUG_STATUS_NO_CHANGE,
}

impl ExecutionStatus {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            DEBUG_STATUS_NO_DEBUGGEE => Some(Self::NoDebuggee),
            DEBUG_STATUS_OUT_OF_SYNC => Some(Self::OutOfSync),
            DEBUG_STATUS_WAIT_INPUT => Some(Self::WaitInput),
            DEBUG_STATUS_TIMEOUT => Some(Self::Timeout),
            DEBUG_STATUS_BREAK => Some(Self::Break),
            DEBUG_STATUS_STEP_INTO => Some(Self::StepInto),
            DEBUG_STATUS_STEP_BRANCH => Some(Self::StepBranch),
            DEBUG_STATUS_STEP_OVER => Some(Self::StepOver),
            DEBUG_STATUS_GO_NOT_HANDLED => Some(Self::GoNotHandled),
            DEBUG_STATUS_GO_HANDLED => Some(Self::GoHandled),
            DEBUG_STATUS_GO => Some(Self::Go),
            DEBUG_STATUS_IGNORE_EVENT => Some(Self::IgnoreEvent),
            DEBUG_STATUS_RESTART_REQUESTED => Some(Self::RestartRequested),
            DEBUG_STATUS_NO_CHANGE => Some(Self::NoChange),
            _ => None,
        }
    }
}
