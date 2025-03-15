use crate::manager::HookHandler;
use crate::util::{virtual_protect, virtual_query};
use papaya::HashMap;
use std::sync::LazyLock;
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
    fn create(target: usize, handler: HookHandler) -> Result<Self, std::io::Error> {
        let old_protection = virtual_query(target)?;

        Ok(Self {
            old_protection,
            target,
            handler,
        })
    }

    pub fn enable(&self) -> Result<(), std::io::Error> {
        self.reapply_hook()
    }

    pub fn reapply_hook(&self) -> Result<(), std::io::Error> {
        virtual_protect(self.target, PAGE_EXECUTE_READ | PAGE_GUARD)
            .map(|_| ())
            .map_err(|e| e)
    }

    pub fn disable(&self) -> Result<(), std::io::Error> {
        virtual_protect(self.target, self.old_protection)
            .map(|_| ())
            .map_err(|e| e)
    }

    pub fn handle(&self, p: *mut EXCEPTION_POINTERS) {
        (self.handler)(p)
    }

    pub fn add_hook(target_address: usize, handler: HookHandler) -> Result<(), std::io::Error> {
        let guard_hook = GuardHook::create(target_address, handler)?;

        let pin = GUARD_HOOK_HASHMAP.pin();
        pin.insert(target_address, guard_hook);
        pin.get(&target_address)
            .map(|hook| hook.enable())
            .unwrap_or(Err(std::io::Error::last_os_error()))?;

        Ok(())
    }

    pub fn remove_hook(target_address: usize) -> Result<(), std::io::Error> {
        let pin = GUARD_HOOK_HASHMAP.pin();
        let hook = pin
            .get(&target_address)
            .ok_or(std::io::Error::last_os_error())?;

        hook.disable()?;
        pin.remove(&target_address);

        Ok(())
    }

    pub fn remove_all_hooks() -> Result<(), std::io::Error> {
        for (k, _v) in GUARD_HOOK_HASHMAP.pin().iter() {
            Self::remove_hook(*k)?;
        }

        Ok(())
    }
}

impl Drop for GuardHook {
    fn drop(&mut self) {
        self.disable().expect("Failed to remove hook");
    }
}

#[cfg(test)]
mod guard_tests {
    use crate::guard::GuardHook;
    use crate::manager::VEHManager;
    use serial_test::serial;
    use std::ptr::null;
    use windows::core::imp::GetProcAddress;

    static TEST_VALUE: std::sync::Mutex<i32> = std::sync::Mutex::new(0);

    fn get_vm() -> VEHManager {
        VEHManager::new().unwrap()
    }

    fn reset_test_value() {
        *TEST_VALUE.lock().unwrap() = 0;
    }

    fn add_get_proc_address_hook() {
        let result = GuardHook::add_hook(GetProcAddress as *const () as usize, |_exception_info| {
            *TEST_VALUE.lock().unwrap() += 1;
        });

        assert_eq!(result.is_ok(), true);
    }

    fn remove_get_proc_address_hook() {
        let result = GuardHook::remove_hook(GetProcAddress as *const () as usize);
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    #[serial]
    fn guard_hook_three_times() {
        reset_test_value();

        let _vm = get_vm();
        let mut current = *TEST_VALUE.lock().unwrap();

        add_get_proc_address_hook();

        for _ in 0..3 {
            assert_eq!(*TEST_VALUE.lock().unwrap(), current);

            unsafe {
                GetProcAddress(0 as _, null());
            }
            assert_eq!(*TEST_VALUE.lock().unwrap(), current + 1);

            current += 1;
        }

        remove_get_proc_address_hook();
    }

    #[test]
    #[serial]
    fn add_remove_add() {
        reset_test_value();

        let _vm = get_vm();
        let current = *TEST_VALUE.lock().unwrap();

        add_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(*TEST_VALUE.lock().unwrap(), current + 1);

        remove_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(*TEST_VALUE.lock().unwrap(), current + 1);

        add_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }

        assert_eq!(*TEST_VALUE.lock().unwrap(), current + 2);

        remove_get_proc_address_hook();
    }

    #[test]
    #[serial]
    fn add_drop() {
        reset_test_value();

        let vm = get_vm();
        let current = *TEST_VALUE.lock().unwrap();

        add_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(*TEST_VALUE.lock().unwrap(), current + 1);

        drop(vm);

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(*TEST_VALUE.lock().unwrap(), current + 1);
    }
}
