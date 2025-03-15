use crate::manager::HookHandler;
use crate::util::{iterate_threads, os_bitness};
use papaya::HashMap;
use std::sync::LazyLock;
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT_DEBUG_REGISTERS_AMD64,
    CONTEXT_DEBUG_REGISTERS_X86, EXCEPTION_POINTERS,
};

pub(crate) static HW_BP_HOOK_HASHMAP: LazyLock<HashMap<usize, HardwareBreakpointHook>> =
    LazyLock::new(|| HashMap::new());

#[derive(Debug, Clone, Copy)]
pub enum HWBreakpointSlot {
    Slot0 = 0,
    Slot1 = 1,
    Slot2 = 2,
    Slot3 = 3,
}

#[derive(Debug, Clone)]
pub struct HardwareBreakpointHook {
    target: usize,
    handler: HookHandler,
    slot: HWBreakpointSlot,
}

// https://github.com/microsoft/win32metadata/issues/1044
#[repr(align(16))]
#[derive(Default)]
struct AlignedContext {
    ctx: windows::Win32::System::Diagnostics::Debug::CONTEXT,
}

impl HardwareBreakpointHook {
    fn create(
        target: usize,
        handler: HookHandler,
        slot: HWBreakpointSlot,
    ) -> Result<Self, std::io::Error> {
        Ok(Self {
            target,
            handler,
            slot,
        })
    }

    pub fn enable(&self) -> Result<(), std::io::Error> {
        let target = self.target;
        let slot = self.slot;
        iterate_threads(Box::new(move |thd| Self::set_breakpoint(thd, target, slot)))
    }

    fn get_context() -> AlignedContext {
        let mut context = AlignedContext::default();

        let reg = if os_bitness() == 64 {
            CONTEXT_DEBUG_REGISTERS_AMD64
        } else {
            CONTEXT_DEBUG_REGISTERS_X86
        };
        context.ctx.ContextFlags = reg;

        context
    }

    pub fn set_breakpoint(
        handle: windows::Win32::Foundation::HANDLE,
        target: usize,
        pos: HWBreakpointSlot,
    ) -> Result<(), std::io::Error> {
        let mut context = Self::get_context();
        let result = unsafe { GetThreadContext(handle, &mut context.ctx) };

        if result.is_err() {
            return Err(std::io::Error::last_os_error());
        }

        let pos_num = pos as u32;

        match pos_num {
            0 => context.ctx.Dr0 = target as u64,
            1 => context.ctx.Dr1 = target as u64,
            2 => context.ctx.Dr2 = target as u64,
            3 => context.ctx.Dr3 = target as u64,
            _ => return Err(std::io::Error::last_os_error()),
        }

        context.ctx.Dr7 &= !(3u64 << (16 + 4 * pos_num as usize));
        context.ctx.Dr7 &= !(3u64 << (18 + 4 * pos_num as usize));
        context.ctx.Dr7 |= 1u64 << (2 * pos_num as usize);

        let result = unsafe { SetThreadContext(handle, &context.ctx) };
        if result.is_err() {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }

    pub fn remove_breakpoint(
        handle: windows::Win32::Foundation::HANDLE,
        target: usize,
        pos: HWBreakpointSlot,
    ) -> Result<(), std::io::Error> {
        let mut context = Self::get_context();
        let result = unsafe { GetThreadContext(handle, &mut context.ctx) };

        if result.is_err() {
            return Err(std::io::Error::last_os_error());
        }

        let pos_num = pos as u32;

        match pos_num {
            0 => {
                if context.ctx.Dr0 == target as u64 {
                    context.ctx.Dr7 &= !(1u64 << (2 * pos_num as usize));
                    context.ctx.Dr0 = 0;
                }
            }
            1 => {
                if context.ctx.Dr1 == target as u64 {
                    context.ctx.Dr7 &= !(1u64 << (2 * pos_num as usize));
                    context.ctx.Dr1 = 0;
                }
            }
            2 => {
                if context.ctx.Dr2 == target as u64 {
                    context.ctx.Dr7 &= !(1u64 << (2 * pos_num as usize));
                    context.ctx.Dr2 = 0;
                }
            }
            3 => {
                if context.ctx.Dr3 == target as u64 {
                    context.ctx.Dr7 &= !(1u64 << (2 * pos_num as usize));
                    context.ctx.Dr3 = 0;
                }
            }
            _ => return Err(std::io::Error::last_os_error()),
        }

        let result = unsafe { SetThreadContext(handle, &context.ctx) };

        if result.is_err() {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }

    pub fn disable(&self) -> Result<(), std::io::Error> {
        let target = self.target;
        let slot = self.slot;
        iterate_threads(Box::new(move |thd| {
            Self::remove_breakpoint(thd, target, slot)
        }))
    }

    pub fn add_hook(
        target_address: usize,
        handler: HookHandler,
        breakpoint_slot: HWBreakpointSlot,
    ) -> Result<(), std::io::Error> {
        let sw_bp_hook = HardwareBreakpointHook::create(target_address, handler, breakpoint_slot)?;

        let pin = HW_BP_HOOK_HASHMAP.pin();
        pin.insert(target_address, sw_bp_hook);
        pin.get(&target_address)
            .map(|hook| hook.enable())
            .unwrap_or(Err(std::io::Error::last_os_error()))?;

        Ok(())
    }

    pub fn remove_hook(target_address: usize) -> Result<(), std::io::Error> {
        let pin = HW_BP_HOOK_HASHMAP.pin();
        let hook = pin
            .get(&target_address)
            .ok_or(std::io::Error::last_os_error())?;

        hook.disable()?;
        pin.remove(&target_address);

        Ok(())
    }

    pub fn remove_all_hooks() -> Result<(), std::io::Error> {
        for (k, _v) in HW_BP_HOOK_HASHMAP.pin().iter() {
            Self::remove_hook(*k)?;
        }

        Ok(())
    }

    pub fn handle(&self, p: *mut EXCEPTION_POINTERS) {
        (self.handler)(p)
    }
}

impl Drop for HardwareBreakpointHook {
    fn drop(&mut self) {
        self.disable().expect("Failed to remove hook");
    }
}

#[cfg(test)]
mod hardware_breakpoint_tests {
    use crate::hardware::{HWBreakpointSlot, HardwareBreakpointHook};
    use crate::manager::VEHManager;
    use serial_test::serial;
    use std::ptr::null;
    use windows::core::imp::GetProcAddress;
    use windows::Win32::System::Threading::GetCurrentProcess;

    static HW_BP_TEST_VALUE: std::sync::Mutex<i32> = std::sync::Mutex::new(0);

    fn get_vm() -> VEHManager {
        VEHManager::new().unwrap()
    }

    fn reset_test_value() {
        *HW_BP_TEST_VALUE.lock().unwrap() = 0;
    }

    fn add_get_proc_address_hook() {
        let result = HardwareBreakpointHook::add_hook(
            GetProcAddress as *const () as usize,
            |_exception_info| {
                *HW_BP_TEST_VALUE.lock().unwrap() += 1;
            },
            HWBreakpointSlot::Slot1,
        );

        assert_eq!(result.is_ok(), true);
    }

    fn remove_get_proc_address_hook() {
        let result = HardwareBreakpointHook::remove_hook(GetProcAddress as *const () as usize);
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    #[serial]
    fn guard_hook_three_times() {
        reset_test_value();

        let _vm = get_vm();
        let mut current = *HW_BP_TEST_VALUE.lock().unwrap();

        add_get_proc_address_hook();

        for _ in 0..3 {
            assert_eq!(*HW_BP_TEST_VALUE.lock().unwrap(), current);

            unsafe {
                GetProcAddress(0 as _, null());
            }
            assert_eq!(*HW_BP_TEST_VALUE.lock().unwrap(), current + 1);

            current += 1;
        }
    }

    #[test]
    #[serial]
    fn add_remove_add() {
        reset_test_value();

        let _vm = get_vm();
        let current = *HW_BP_TEST_VALUE.lock().unwrap();

        add_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(*HW_BP_TEST_VALUE.lock().unwrap(), current + 1);

        remove_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(*HW_BP_TEST_VALUE.lock().unwrap(), current + 1);

        add_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }

        assert_eq!(*HW_BP_TEST_VALUE.lock().unwrap(), current + 2);
    }

    #[test]
    #[serial]
    fn add_drop() {
        reset_test_value();

        let vm = get_vm();
        let current = *HW_BP_TEST_VALUE.lock().unwrap();

        add_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }

        assert_eq!(*HW_BP_TEST_VALUE.lock().unwrap(), current + 1);

        drop(vm);

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(*HW_BP_TEST_VALUE.lock().unwrap(), current + 1);
    }

    #[test]
    #[serial]
    fn add_multiple_hooks() {
        reset_test_value();

        let _vm = get_vm();
        let current = *HW_BP_TEST_VALUE.lock().unwrap();

        let result = HardwareBreakpointHook::add_hook(
            GetProcAddress as *const () as usize,
            |_exception_info| {
                *HW_BP_TEST_VALUE.lock().unwrap() += 1;
            },
            HWBreakpointSlot::Slot1,
        );

        assert_eq!(result.is_ok(), true);

        let result = HardwareBreakpointHook::add_hook(
            GetCurrentProcess as *const () as usize,
            |_exception_info| {
                *HW_BP_TEST_VALUE.lock().unwrap() += 1;
            },
            HWBreakpointSlot::Slot2,
        );

        assert_eq!(result.is_ok(), true);

        unsafe {
            GetProcAddress(0 as _, null());
            GetCurrentProcess();
        }

        assert_eq!(*HW_BP_TEST_VALUE.lock().unwrap(), current + 2);
    }
}
