use crate::guard::GuardHook;
use crate::handler::veh_handler;
use crate::hardware::HardwareBreakpointHook;
use crate::hook_base::{HookBase, HookError};
use crate::software::SoftwareBreakpointHook;
use indexmap::IndexMap;
use std::sync::RwLock;
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS,
};

pub type HookHandler = fn(*mut EXCEPTION_POINTERS) -> Option<i32>;

pub(crate) static VEH_CALLBACK: RwLock<Option<IndexMap<usize, HookHandler>>> = RwLock::new(None);

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

    pub fn add_callback(&self, id: usize, handler: HookHandler) -> Result<(), HookError> {
        let mut map = VEH_CALLBACK.write().map_err(|_| HookError::PoisonError)?;
        if map.is_none() {
            *map = Some(IndexMap::new());
        }

        map.as_mut().unwrap().insert(id, handler);

        Ok(())
    }

    pub fn remove_callback(&self, id: usize) -> Result<(), HookError> {
        let mut map = VEH_CALLBACK.write().map_err(|_| HookError::PoisonError)?;
        if let Some(map) = map.as_mut() {
            map.shift_remove(&id);
        }

        Ok(())
    }

    pub fn trigger_callbacks(p: *mut EXCEPTION_POINTERS) -> Result<Option<i32>, HookError> {
        let map = VEH_CALLBACK.read().map_err(|_| HookError::PoisonError)?;

        if let Some(map) = map.as_ref() {
            for handler in map.values() {
                if let Some(result) = handler(p) {
                    return Ok(Some(result));
                }
            }
        }

        Ok(None)
    }
}

impl Drop for VEHManager {
    fn drop(&mut self) {
        #[cfg(feature = "log")]
        log::debug!("Removing VEH handler");

        let result = self.remove_all_hooks();

        if let Err(e) = result {
            #[cfg(feature = "log")]
            log::error!("Error removing hooks: {:?}", e);
        }

        let r = unsafe { RemoveVectoredExceptionHandler(self.veh_handle) };

        if r == 0 {
            #[cfg(feature = "log")]
            log::error!(
                "Failed to remove VEH handler: {:?}",
                std::io::Error::last_os_error()
            );
        }
    }
}

#[cfg(test)]
mod veh_manager_tests {
    use super::*;
    use crate::base_tests::BaseTest;
    use serial_test::serial;

    static VM_TEST_VALUE: std::sync::Mutex<i32> = std::sync::Mutex::new(0);

    struct VEHManagerTests;

    impl VEHManagerTests {
        fn test_callback() {
            let vm = VEHManager::new().unwrap();
            Self::reset_test_value();

            vm.add_callback(1, |_p| {
                *VM_TEST_VALUE.lock().unwrap() += 1;
                None
            })
            .expect("Failed to add callback");
            let result = vm.add_hardware_breakpoint_hook(Self::get_test_fn_address(), |_p| None);

            Self::call_test_fn();

            vm.remove_hardware_breakpoint_hook(Self::get_test_fn_address())
                .unwrap();

            assert!(result.is_ok());
            assert_eq!(Self::get_test_value(), 1);
        }

        fn test_multiple_callbacks() {
            let vm = VEHManager::new().unwrap();
            Self::reset_test_value();

            vm.add_callback(1, |_p| {
                *VM_TEST_VALUE.lock().unwrap() += 1;
                None
            })
            .expect("Failed to add callback 1");

            vm.add_callback(2, |_p| {
                *VM_TEST_VALUE.lock().unwrap() += 1;
                None
            })
            .expect("Failed to add callback 2");

            vm.add_callback(3, |_p| {
                *VM_TEST_VALUE.lock().unwrap() += 1;
                None
            })
            .expect("Failed to add callback 3");
            let result = vm.add_hardware_breakpoint_hook(Self::get_test_fn_address(), |_p| None);

            Self::call_test_fn();

            vm.remove_hardware_breakpoint_hook(Self::get_test_fn_address())
                .unwrap();

            vm.remove_callback(1).expect("Failed to remove callback 1");
            vm.remove_callback(2).expect("Failed to remove callback 2");
            vm.remove_callback(3).expect("Failed to remove callback 3");
            assert!(result.is_ok());
            assert_eq!(Self::get_test_value(), 3);
        }

        fn toggle_software_breakpoint_hook() {
            let vm = VEHManager::new().unwrap();
            Self::reset_test_value();
            let result = vm.add_software_breakpoint_hook(Self::get_test_fn_address(), |_p| {
                *VM_TEST_VALUE.lock().unwrap() += 1;
                None
            });

            Self::call_test_fn();

            assert!(result.is_ok());
            assert_eq!(Self::get_test_value(), 1);

            let result = vm.remove_software_breakpoint_hook(Self::get_test_fn_address());
            assert!(result.is_ok());
        }

        fn toggle_hardware_breakpoint_hook() {
            let vm = VEHManager::new().unwrap();
            Self::reset_test_value();
            let result = vm.add_hardware_breakpoint_hook(Self::get_test_fn_address(), |_p| {
                *VM_TEST_VALUE.lock().unwrap() += 1;
                None
            });

            Self::call_test_fn();

            assert!(result.is_ok());
            assert_eq!(Self::get_test_value(), 1);

            let result = vm.remove_hardware_breakpoint_hook(Self::get_test_fn_address());
            assert!(result.is_ok());
        }

        fn _toggle_guard_hook() {
            let vm = VEHManager::new().unwrap();
            Self::reset_test_value();
            let result = vm.add_guard_hook(Self::get_test_fn_address(), |_p| {
                *VM_TEST_VALUE.lock().unwrap() += 1;
                None
            });

            Self::call_test_fn();

            assert!(result.is_ok());
            assert_eq!(Self::get_test_value(), 1);

            let result = vm.remove_guard_hook(Self::get_test_fn_address());
            assert!(result.is_ok());
        }
    }

    impl BaseTest for VEHManagerTests {
        fn reset_test_value() {
            *VEH_CALLBACK.write().unwrap() = None;
            *VM_TEST_VALUE.lock().unwrap() = 0;
        }

        fn get_test_value() -> i32 {
            *VM_TEST_VALUE.lock().unwrap()
        }

        fn set_test_value(value: i32) {
            *VM_TEST_VALUE.lock().unwrap() = value;
        }

        fn add_hook() {
            unimplemented!()
        }

        fn remove_hook() {
            unimplemented!()
        }
    }

    #[test]
    #[serial]
    fn test_callback() {
        VEHManagerTests::test_callback();
    }

    #[test]
    #[serial]
    fn test_multiple_callbacks() {
        VEHManagerTests::test_multiple_callbacks();
    }

    #[test]
    #[serial]
    fn toggle_guard_hook() {
        //VEHManagerTests::toggle_guard_hook();
    }

    #[test]
    #[serial]
    fn toggle_software_breakpoint_hook() {
        VEHManagerTests::toggle_software_breakpoint_hook();
    }

    #[test]
    #[serial]
    fn toggle_hardware_breakpoint_hook() {
        VEHManagerTests::toggle_hardware_breakpoint_hook();
    }
}
