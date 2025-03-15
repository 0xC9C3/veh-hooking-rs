use crate::guard::GuardHook;
use crate::handler::veh_handler;
use crate::hardware::HardwareBreakpointHook;
use crate::software::SoftwareBreakpointHook;
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION,
    EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
};

pub type HookHandler = fn(*mut EXCEPTION_POINTERS);

pub struct VEHManager {
    veh_handle: *mut core::ffi::c_void,
}

impl VEHManager {
    pub fn new() -> Result<Self, std::io::Error> {
        Self::new_with_first(1)
    }

    pub fn new_with_first(first: u32) -> Result<Self, std::io::Error> {
        let veh_handle = unsafe { AddVectoredExceptionHandler(first, Some(veh_handler)) };
        if veh_handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self { veh_handle })
    }

    pub fn add_guard_hook(
        &self,
        target_address: usize,
        handler: HookHandler,
    ) -> Result<(), std::io::Error> {
        GuardHook::add_hook(target_address, handler)
    }

    pub fn remove_guard_hook(&self, target_address: usize) -> Result<(), std::io::Error> {
        GuardHook::remove_hook(target_address)
    }

    pub fn add_hardware_hook(
        &self,
        target_address: usize,
        handler: HookHandler,
        slot: crate::hardware::HWBreakpointSlot,
    ) -> Result<(), std::io::Error> {
        HardwareBreakpointHook::add_hook(target_address, handler, slot)
    }

    pub fn remove_hardware_hook(&self, target_address: usize) -> Result<(), std::io::Error> {
        HardwareBreakpointHook::remove_hook(target_address)
    }

    pub fn add_software_hook(
        &self,
        target_address: usize,
        handler: HookHandler,
    ) -> Result<(), std::io::Error> {
        SoftwareBreakpointHook::add_hook(target_address, handler)
    }

    pub fn remove_software_hook(&self, target_address: usize) -> Result<(), std::io::Error> {
        SoftwareBreakpointHook::remove_hook(target_address)
    }

    pub fn remove_all_hooks(&self) -> Result<(), std::io::Error> {
        GuardHook::remove_all_hooks()?;
        SoftwareBreakpointHook::remove_all_hooks()?;
        HardwareBreakpointHook::remove_all_hooks()?;

        Ok(())
    }
}

impl Drop for VEHManager {
    fn drop(&mut self) {
        self.remove_all_hooks().expect("Failed to remove hooks");

        unsafe {
            RemoveVectoredExceptionHandler(self.veh_handle);
        }
    }
}

pub fn veh_continue() -> i32 {
    EXCEPTION_CONTINUE_EXECUTION
}

pub fn veh_continue_search() -> i32 {
    EXCEPTION_CONTINUE_SEARCH
}

pub fn veh_continue_step(p: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        (*(*p).ContextRecord).EFlags |= 0x100;
    }

    EXCEPTION_CONTINUE_EXECUTION
}

pub fn veh_continue_hwbp(p: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        (*(*p).ContextRecord).EFlags |= 1 << 16;
    }

    EXCEPTION_CONTINUE_EXECUTION
}
