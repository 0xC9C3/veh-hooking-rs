use crate::hook_base::HookError::HookNotFound;
use crate::hook_base::{veh_continue, veh_continue_step, HookBase, HookError};
use crate::manager::HookHandler;
use crate::util::{virtual_protect, virtual_query};
use papaya::HashMap;
use std::sync::LazyLock;
use windows::Win32::Foundation::{NTSTATUS, STATUS_GUARD_PAGE_VIOLATION, STATUS_SINGLE_STEP};
use windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;
use windows::Win32::System::Memory::{PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_PROTECTION_FLAGS};

#[derive(Debug, Clone)]
pub struct GuardHook {
    old_protection: PAGE_PROTECTION_FLAGS,
    target: usize,
    handler: HookHandler,
}

pub(crate) static GUARD_HOOK_HASHMAP: LazyLock<HashMap<usize, GuardHook>> =
    LazyLock::new(|| HashMap::new());

impl GuardHook {
    fn create(target: usize, handler: HookHandler) -> Result<Self, HookError> {
        let old_protection = virtual_query(target)?;

        Ok(Self {
            old_protection,
            target,
            handler,
        })
    }

    pub(crate) fn reapply_hook(&self) -> Result<(), HookError> {
        virtual_protect(self.target, PAGE_EXECUTE_READ | PAGE_GUARD)
            .map(|_| ())
            .map_err(|e| HookError::from(e))
    }
}

impl HookBase for GuardHook {
    fn enable(&self) -> Result<(), HookError> {
        self.reapply_hook()
    }
    fn disable(&self) -> Result<(), HookError> {
        virtual_protect(self.target, self.old_protection)
            .map(|_| ())
            .map_err(|e| HookError::from(e))
    }
    fn handle(&self, p: *mut EXCEPTION_POINTERS) -> Option<i32> {
        (self.handler)(p)
    }

    fn add_hook(target_address: usize, handler: HookHandler) -> Result<(), HookError> {
        let guard_hook = GuardHook::create(target_address, handler)?;

        let pin = GUARD_HOOK_HASHMAP.pin();
        pin.insert(target_address, guard_hook);
        pin.get(&target_address)
            .map(|hook| hook.enable())
            .unwrap_or(Err(HookError::from(std::io::Error::last_os_error())))?;

        Ok(())
    }

    fn remove_hook(target_address: usize) -> Result<(), HookError> {
        let pin = GUARD_HOOK_HASHMAP.pin();
        let hook = pin.get(&target_address).ok_or(HookNotFound)?;

        hook.disable()?;
        pin.remove(&target_address);

        Ok(())
    }

    fn remove_all_hooks() -> Result<(), HookError> {
        for (k, _v) in GUARD_HOOK_HASHMAP.pin().iter() {
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
            STATUS_GUARD_PAGE_VIOLATION => {
                let result = GUARD_HOOK_HASHMAP
                    .pin()
                    .get(&rip)
                    .map(|hook| hook.handle(exception_info))
                    .unwrap_or(None);

                if let Some(result) = result {
                    return Some(result);
                }

                Some(veh_continue_step(exception_info))
            }
            STATUS_SINGLE_STEP => {
                GUARD_HOOK_HASHMAP.pin().iter().for_each(|(_, hook)| {
                    hook.reapply_hook().expect("Failed to reapply hook");
                });

                Some(veh_continue())
            }
            _ => None,
        }
    }
}

impl Drop for GuardHook {
    fn drop(&mut self) {
        self.disable().expect("Failed to remove hook");
    }
}

#[cfg(test)]
mod guard_tests {
    use crate::base_tests::BaseTest;
    use crate::guard::GuardHook;
    use crate::hook_base::HookBase;
    use serial_test::serial;
    use windows::core::imp::GetProcAddress;

    static TEST_VALUE: std::sync::Mutex<i32> = std::sync::Mutex::new(0);

    struct GuardHookTests;
    impl BaseTest for GuardHookTests {
        fn reset_test_value() {
            *TEST_VALUE.lock().unwrap() = 0;
        }

        fn get_test_value() -> i32 {
            *TEST_VALUE.lock().unwrap()
        }

        fn set_test_value(value: i32) {
            *TEST_VALUE.lock().unwrap() = value;
        }

        fn add_get_proc_address_hook() {
            let result =
                GuardHook::add_hook(GetProcAddress as *const () as usize, |_exception_info| {
                    *TEST_VALUE.lock().unwrap() += 1;

                    None
                });

            assert_eq!(result.is_ok(), true);
        }

        fn remove_get_proc_address_hook() {
            let result = GuardHook::remove_hook(GetProcAddress as *const () as usize);
            assert_eq!(result.is_ok(), true);
        }
    }

    #[test]
    #[serial]
    fn hook_three_times() {
        GuardHookTests::hook_three_times()
    }

    #[test]
    #[serial]
    fn add_remove_add() {
        GuardHookTests::add_remove_add()
    }

    #[test]
    #[serial]
    fn add_drop() {
        GuardHookTests::add_drop()
    }
}
