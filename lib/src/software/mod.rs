use crate::hook_base::{veh_continue, veh_continue_step, HookBase, HookError};
use crate::manager::HookHandler;
use crate::util::{get_next_instruction_offset, virtual_protect, virtual_query};
use papaya::HashMap;
use std::sync::LazyLock;
use windows::Win32::Foundation::{NTSTATUS, STATUS_BREAKPOINT, STATUS_SINGLE_STEP};
use windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;
use windows::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};

pub(crate) static SW_BP_HOOK_HASHMAP: LazyLock<HashMap<usize, SoftwareBreakpointHook>> =
    LazyLock::new(|| HashMap::new());

#[derive(Debug, Clone)]
pub struct SoftwareBreakpointHook {
    old_protection: PAGE_PROTECTION_FLAGS,
    original_byte: u8,
    target: usize,
    handler: HookHandler,
}

impl SoftwareBreakpointHook {
    const X86_BREAKPOINT: u8 = 0xCC;
    fn create(target: usize, handler: HookHandler) -> Result<Self, std::io::Error> {
        let old_protection = virtual_query(target)?;
        let original_byte: u8 = unsafe { *((target) as *const u8) };

        Ok(Self {
            old_protection,
            target,
            handler,
            original_byte,
        })
    }

    pub fn get_next_instruction_offset(&self) -> Result<usize, std::io::Error> {
        get_next_instruction_offset(self.target)
    }

    pub fn enable(&self) -> Result<(), HookError> {
        self.set_byte(0xCC)
    }

    pub fn disable(&self) -> Result<(), HookError> {
        self.set_byte(self.original_byte)
    }

    fn set_byte(&self, byte: u8) -> Result<(), HookError> {
        virtual_protect(self.target, PAGE_EXECUTE_READWRITE)
            .map(|_| ())
            .map_err(|e| e)?;
        unsafe { *((self.target) as *mut u8) = byte };
        virtual_protect(self.target, self.old_protection)
            .map(|_| ())
            .map_err(|e| HookError::from(e))
    }

    pub fn handle(&self, p: *mut EXCEPTION_POINTERS) -> Option<i32> {
        (self.handler)(p)
    }

    pub fn remove_hook(target_address: usize) -> Result<(), HookError> {
        let pin = SW_BP_HOOK_HASHMAP.pin();
        let hook = pin
            .get(&target_address)
            .ok_or(std::io::Error::last_os_error())?;

        hook.disable()?;
        pin.remove(&hook.get_next_instruction_offset()?);
        pin.remove(&target_address);

        Ok(())
    }

    pub fn remove_all_hooks() -> Result<(), HookError> {
        for (k, _v) in SW_BP_HOOK_HASHMAP.pin().iter() {
            Self::remove_hook(*k)?;
        }

        Ok(())
    }
}

impl HookBase for SoftwareBreakpointHook {
    fn add_hook(target_address: usize, handler: HookHandler) -> Result<(), HookError> {
        let sw_bp_hook = SoftwareBreakpointHook::create(target_address, handler)?;
        let sw_bp_hook_next_address = sw_bp_hook.get_next_instruction_offset()?;

        let pin = SW_BP_HOOK_HASHMAP.pin();
        pin.insert(sw_bp_hook_next_address, sw_bp_hook.clone());
        pin.insert(target_address, sw_bp_hook);
        pin.get(&target_address)
            .map(|hook| hook.enable())
            .unwrap_or(Err(HookError::from(std::io::Error::last_os_error())))?;

        Ok(())
    }
    fn enable(&self) -> Result<(), HookError> {
        self.set_byte(Self::X86_BREAKPOINT)
    }

    fn disable(&self) -> Result<(), HookError> {
        self.set_byte(self.original_byte)
    }

    fn handle(&self, p: *mut EXCEPTION_POINTERS) -> Option<i32> {
        (self.handler)(p)
    }

    fn remove_hook(target_address: usize) -> Result<(), HookError> {
        let pin = SW_BP_HOOK_HASHMAP.pin();
        let hook = pin
            .get(&target_address)
            .ok_or(std::io::Error::last_os_error())?;

        hook.disable()?;
        pin.remove(&hook.get_next_instruction_offset()?);
        pin.remove(&target_address);

        Ok(())
    }

    fn remove_all_hooks() -> Result<(), HookError> {
        for (k, _v) in SW_BP_HOOK_HASHMAP.pin().iter() {
            Self::remove_hook(*k)?;
        }

        Ok(())
    }

    fn handle_event(
        rip: usize,
        status: NTSTATUS,
        exception_info: *mut EXCEPTION_POINTERS,
    ) -> Option<i32> {
        match status {
            STATUS_BREAKPOINT => {
                let result = SW_BP_HOOK_HASHMAP
                    .pin()
                    .get(&rip)
                    .map(|hook| {
                        let result = hook.handle(exception_info);
                        let _ = hook.disable();
                        return result;
                    })
                    .unwrap_or(None);

                if let Some(result) = result {
                    return Some(result);
                }

                Some(veh_continue_step(exception_info))
            }
            STATUS_SINGLE_STEP => {
                let rip = unsafe { (*(*exception_info).ContextRecord).Rip as usize };
                if let Some(hook) = SW_BP_HOOK_HASHMAP.pin().get(&rip) {
                    hook.enable().expect("Failed to reapply hook");
                    return Some(veh_continue());
                }

                None
            }
            _ => None,
        }
    }
}

impl Drop for SoftwareBreakpointHook {
    fn drop(&mut self) {
        self.disable().expect("Failed to remove hook");
    }
}

#[cfg(test)]
mod software_breakpoint_tests {
    use crate::base_tests::BaseTest;
    use crate::hook_base::HookBase;
    use crate::software::SoftwareBreakpointHook;
    use serial_test::serial;
    use windows::core::imp::GetProcAddress;

    static SW_BP_TEST_VALUE: std::sync::Mutex<i32> = std::sync::Mutex::new(0);

    struct SWBPHookTests;
    impl BaseTest for SWBPHookTests {
        fn reset_test_value() {
            *SW_BP_TEST_VALUE.lock().unwrap() = 0;
        }

        fn get_test_value() -> i32 {
            *SW_BP_TEST_VALUE.lock().unwrap()
        }

        fn set_test_value(value: i32) {
            *SW_BP_TEST_VALUE.lock().unwrap() = value;
        }

        fn add_get_proc_address_hook() {
            let result = SoftwareBreakpointHook::add_hook(
                GetProcAddress as *const () as usize,
                |_exception_info| {
                    *SW_BP_TEST_VALUE.lock().unwrap() += 1;

                    None
                },
            );

            assert_eq!(result.is_ok(), true);
        }

        fn remove_get_proc_address_hook() {
            let result = SoftwareBreakpointHook::remove_hook(GetProcAddress as *const () as usize);
            assert_eq!(result.is_ok(), true);
        }
    }

    #[test]
    #[serial]
    fn hook_three_times() {
        SWBPHookTests::hook_three_times()
    }

    #[test]
    #[serial]
    fn add_remove_add() {
        SWBPHookTests::add_remove_add()
    }

    #[test]
    #[serial]
    fn add_drop() {
        SWBPHookTests::add_drop()
    }
}
