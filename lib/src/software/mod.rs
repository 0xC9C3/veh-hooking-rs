use crate::manager::HookHandler;
use crate::util::{get_next_instruction_offset, virtual_protect, virtual_query};
use papaya::HashMap;
use std::sync::LazyLock;
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

    pub fn enable(&self) -> Result<(), std::io::Error> {
        self.set_byte(0xCC)
    }

    pub fn disable(&self) -> Result<(), std::io::Error> {
        self.set_byte(self.original_byte)
    }

    fn set_byte(&self, byte: u8) -> Result<(), std::io::Error> {
        virtual_protect(self.target, PAGE_EXECUTE_READWRITE)
            .map(|_| ())
            .map_err(|e| e)?;
        unsafe { *((self.target) as *mut u8) = byte };
        virtual_protect(self.target, self.old_protection)
            .map(|_| ())
            .map_err(|e| e)
    }

    pub fn handle(&self, p: *mut EXCEPTION_POINTERS) {
        (self.handler)(p)
    }

    pub fn add_hook(target_address: usize, handler: HookHandler) -> Result<(), std::io::Error> {
        let sw_bp_hook = SoftwareBreakpointHook::create(target_address, handler)?;
        let sw_bp_hook_next_address = sw_bp_hook.get_next_instruction_offset()?;

        let pin = SW_BP_HOOK_HASHMAP.pin();
        pin.insert(sw_bp_hook_next_address, sw_bp_hook.clone());
        pin.insert(target_address, sw_bp_hook);
        pin.get(&target_address)
            .map(|hook| hook.enable())
            .unwrap_or(Err(std::io::Error::last_os_error()))?;

        Ok(())
    }

    pub fn remove_hook(target_address: usize) -> Result<(), std::io::Error> {
        let pin = SW_BP_HOOK_HASHMAP.pin();
        let hook = pin
            .get(&target_address)
            .ok_or(std::io::Error::last_os_error())?;

        hook.disable()?;
        pin.remove(&hook.get_next_instruction_offset()?);
        pin.remove(&target_address);

        Ok(())
    }

    pub fn remove_all_hooks() -> Result<(), std::io::Error> {
        for (k, _v) in SW_BP_HOOK_HASHMAP.pin().iter() {
            Self::remove_hook(*k)?;
        }

        Ok(())
    }
}

impl Drop for SoftwareBreakpointHook {
    fn drop(&mut self) {
        self.disable().expect("Failed to remove hook");
    }
}

#[cfg(test)]
mod software_breakpoint_tests {
    use crate::manager::VEHManager;
    use crate::software::SoftwareBreakpointHook;
    use serial_test::serial;
    use std::ptr::null;
    use windows::core::imp::GetProcAddress;

    static SW_BP_TEST_VALUE: std::sync::Mutex<i32> = std::sync::Mutex::new(0);

    fn get_vm() -> VEHManager {
        VEHManager::new().unwrap()
    }

    fn reset_test_value() {
        *SW_BP_TEST_VALUE.lock().unwrap() = 0;
    }

    fn add_get_proc_address_hook() {
        let result = SoftwareBreakpointHook::add_hook(
            GetProcAddress as *const () as usize,
            |_exception_info| {
                *SW_BP_TEST_VALUE.lock().unwrap() += 1;
            },
        );

        assert_eq!(result.is_ok(), true);
    }

    fn remove_get_proc_address_hook() {
        let result = SoftwareBreakpointHook::remove_hook(GetProcAddress as *const () as usize);
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    #[serial]
    fn guard_hook_three_times() {
        reset_test_value();

        let _vm = get_vm();
        let mut current = *SW_BP_TEST_VALUE.lock().unwrap();

        add_get_proc_address_hook();

        for _ in 0..3 {
            assert_eq!(*SW_BP_TEST_VALUE.lock().unwrap(), current);

            unsafe {
                GetProcAddress(0 as _, null());
            }
            assert_eq!(*SW_BP_TEST_VALUE.lock().unwrap(), current + 1);

            current += 1;
        }
    }

    #[test]
    #[serial]
    fn add_remove_add() {
        reset_test_value();

        let _vm = get_vm();
        let current = *SW_BP_TEST_VALUE.lock().unwrap();

        add_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(*SW_BP_TEST_VALUE.lock().unwrap(), current + 1);

        remove_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(*SW_BP_TEST_VALUE.lock().unwrap(), current + 1);

        add_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }

        assert_eq!(*SW_BP_TEST_VALUE.lock().unwrap(), current + 2);
    }

    #[test]
    #[serial]
    fn add_drop() {
        reset_test_value();

        let vm = get_vm();
        let current = *SW_BP_TEST_VALUE.lock().unwrap();

        add_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }

        assert_eq!(*SW_BP_TEST_VALUE.lock().unwrap(), current + 1);

        drop(vm);

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(*SW_BP_TEST_VALUE.lock().unwrap(), current + 1);
    }
}
