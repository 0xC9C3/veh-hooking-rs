use crate::manager::HookHandler;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::System::Diagnostics::Debug::{
    EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
};

#[derive(Debug)]
pub enum HookError {
    IoError(std::io::Error),
    HookError(String),
    HookNotFound,
}

impl From<std::io::Error> for HookError {
    fn from(e: std::io::Error) -> Self {
        HookError::IoError(e)
    }
}

pub trait HookBase {
    fn enable(&self) -> Result<(), HookError>;

    fn disable(&self) -> Result<(), HookError>;

    fn handle(&self, p: *mut EXCEPTION_POINTERS) -> Option<i32>;

    fn add_hook(target_address: usize, handler: HookHandler) -> Result<(), HookError>;

    fn remove_hook(target_address: usize) -> Result<(), HookError>;

    fn remove_all_hooks() -> Result<(), HookError>;

    fn handle_event(rip: usize, status: NTSTATUS, p: *mut EXCEPTION_POINTERS) -> Option<i32>;
}

pub fn veh_continue() -> i32 {
    EXCEPTION_CONTINUE_EXECUTION
}

pub fn veh_continue_search() -> i32 {
    EXCEPTION_CONTINUE_SEARCH
}

pub fn veh_continue_step(p: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        (*(*p).ContextRecord).EFlags |= 1 << 8;
    }

    EXCEPTION_CONTINUE_EXECUTION
}

pub fn veh_continue_hwbp(p: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        (*(*p).ContextRecord).EFlags |= 1 << 16;
    }

    EXCEPTION_CONTINUE_EXECUTION
}
