use crate::guard::GuardHook;
use crate::handler::veh_handler;
use crate::hardware::HardwareBreakpointHook;
use crate::hook_base::{HookBase, HookError};
use crate::software::SoftwareBreakpointHook;
use papaya::HashMap;
use std::sync::LazyLock;
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS,
};

pub type HookHandler = fn(*mut EXCEPTION_POINTERS) -> Option<i32>;

pub(crate) static VEH_CALLBACK: LazyLock<HashMap<usize, HookHandler>> =
    LazyLock::new(|| HashMap::new());

pub struct VEHManager {
    veh_handle: *mut core::ffi::c_void,
}

impl VEHManager {
    pub fn new() -> Result<Self, HookError> {
        Self::new_with_first(1)
    }

    pub fn new_with_first(first: u32) -> Result<Self, HookError> {
        let veh_handle = unsafe { AddVectoredExceptionHandler(first, Some(veh_handler)) };
        if veh_handle.is_null() {
            return Err(HookError::from(std::io::Error::last_os_error()));
        }

        Ok(Self { veh_handle })
    }

    pub fn add_guard_hook(
        &self,
        target_address: usize,
        handler: HookHandler,
    ) -> Result<(), HookError> {
        GuardHook::add_hook(target_address, handler)
    }

    pub fn remove_guard_hook(&self, target_address: usize) -> Result<(), HookError> {
        GuardHook::remove_hook(target_address)
    }

    pub fn add_hardware_breakpoint_hook(
        &self,
        target_address: usize,
        handler: HookHandler,
    ) -> Result<(), HookError> {
        HardwareBreakpointHook::add_hook(target_address, handler)
    }

    pub fn remove_hardware_breakpoint_hook(&self, target_address: usize) -> Result<(), HookError> {
        HardwareBreakpointHook::remove_hook(target_address)
    }

    pub fn add_software_breakpoint_hook(
        &self,
        target_address: usize,
        handler: HookHandler,
    ) -> Result<(), HookError> {
        SoftwareBreakpointHook::add_hook(target_address, handler)
    }

    pub fn remove_software_breakpoint_hook(&self, target_address: usize) -> Result<(), HookError> {
        SoftwareBreakpointHook::remove_hook(target_address)
    }

    pub fn remove_all_hooks(&self) -> Result<(), HookError> {
        GuardHook::remove_all_hooks()?;
        SoftwareBreakpointHook::remove_all_hooks()?;
        HardwareBreakpointHook::remove_all_hooks()?;

        Ok(())
    }

    pub fn add_callback(&self, id: usize, handler: HookHandler) {
        VEH_CALLBACK.pin().insert(id, handler);
    }

    pub fn remove_callback(&self, id: usize) {
        VEH_CALLBACK.pin().remove(&id);
    }

    pub fn trigger_callbacks(p: *mut EXCEPTION_POINTERS) -> Option<i32> {
        // sort by id and call
        let mut keys: Vec<usize> = VEH_CALLBACK.pin().keys().copied().collect();
        keys.sort();

        for key in keys {
            if let Some(handler) = VEH_CALLBACK.pin().get(&key) {
                if let Some(result) = handler(p) {
                    return Some(result);
                }
            }
        }

        None
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

#[cfg(test)]
mod veh_manager_tests {
    use super::*;
    use serial_test::serial;
    use std::ptr::null;
    use windows::core::imp::GetProcAddress;
    static VM_TEST_VALUE: std::sync::Mutex<i32> = std::sync::Mutex::new(0);

    fn reset_test_value() {
        *VM_TEST_VALUE.lock().unwrap() = 0;
    }

    fn get_test_value() -> i32 {
        *VM_TEST_VALUE.lock().unwrap()
    }

    #[test]
    #[serial]
    fn test_callback() {
        let vm = VEHManager::new().unwrap();
        reset_test_value();

        vm.add_callback(1, |_p| {
            *VM_TEST_VALUE.lock().unwrap() += 1;
            None
        });

        let result =
            vm.add_hardware_breakpoint_hook(GetProcAddress as *const () as usize, |_p| None);

        unsafe {
            GetProcAddress(0 as _, null());
        }

        assert!(result.is_ok());
        assert_eq!(get_test_value(), 1);
    }
}
