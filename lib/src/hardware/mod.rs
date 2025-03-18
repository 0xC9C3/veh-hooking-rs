use crate::hook_base::HookError::UnknownHardwareBreakpointSlot;
use crate::hook_base::{veh_continue_hwbp, HookBase, HookError};
use crate::manager::HookHandler;
use crate::util::{iterate_threads, os_bitness};
use papaya::HashMap;
use std::sync::LazyLock;
use windows::Win32::Foundation::{NTSTATUS, STATUS_SINGLE_STEP};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT_DEBUG_REGISTERS_AMD64,
    CONTEXT_DEBUG_REGISTERS_X86, EXCEPTION_POINTERS,
};

pub(crate) static HW_BP_HOOK_HASHMAP: LazyLock<HashMap<usize, HardwareBreakpointHook>> =
    LazyLock::new(|| HashMap::new());

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

impl AlignedContext {
    fn with_context_flags() -> Self {
        let mut context = Self::default();
        let reg = if os_bitness() == 64 {
            CONTEXT_DEBUG_REGISTERS_AMD64
        } else {
            CONTEXT_DEBUG_REGISTERS_X86
        };
        context.ctx.ContextFlags = reg;

        context
    }
}

impl HardwareBreakpointHook {
    fn create(
        target: usize,
        handler: HookHandler,
        slot: HWBreakpointSlot,
    ) -> Result<Self, HookError> {
        Ok(Self {
            target,
            handler,
            slot,
        })
    }

    pub fn enable(&self) -> Result<(), HookError> {
        let target = self.target;
        let slot = self.slot;
        iterate_threads(Box::new(move |thd| Self::set_breakpoint(thd, target, slot)))
    }

    pub fn set_breakpoint(
        handle: windows::Win32::Foundation::HANDLE,
        target: usize,
        pos: HWBreakpointSlot,
    ) -> Result<(), HookError> {
        let mut context = AlignedContext::with_context_flags();
        unsafe { GetThreadContext(handle, &mut context.ctx) }?;

        let pos_num = pos as u32;

        match pos_num {
            0 => context.ctx.Dr0 = target as u64,
            1 => context.ctx.Dr1 = target as u64,
            2 => context.ctx.Dr2 = target as u64,
            3 => context.ctx.Dr3 = target as u64,
            _ => return Err(UnknownHardwareBreakpointSlot),
        }

        context.ctx.Dr7 &= !(3u64 << (16 + 4 * pos_num as usize));
        context.ctx.Dr7 &= !(3u64 << (18 + 4 * pos_num as usize));
        context.ctx.Dr7 |= 1u64 << (2 * pos_num as usize);

        unsafe { SetThreadContext(handle, &context.ctx) }?;

        Ok(())
    }

    pub fn remove_breakpoint(
        handle: windows::Win32::Foundation::HANDLE,
        target: usize,
        pos: HWBreakpointSlot,
    ) -> Result<(), HookError> {
        let mut context = AlignedContext::with_context_flags();
        unsafe { GetThreadContext(handle, &mut context.ctx) }?;

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
            _ => return Err(UnknownHardwareBreakpointSlot),
        }

        unsafe { SetThreadContext(handle, &context.ctx) }?;

        Ok(())
    }

    pub fn disable(&self) -> Result<(), HookError> {
        let target = self.target;
        let slot = self.slot;
        iterate_threads(Box::new(move |thd| {
            Self::remove_breakpoint(thd, target, slot)
        }))
    }

    pub fn add_hook_at_slot(
        target_address: usize,
        handler: HookHandler,
        breakpoint_slot: HWBreakpointSlot,
    ) -> Result<(), HookError> {
        let sw_bp_hook = HardwareBreakpointHook::create(target_address, handler, breakpoint_slot)?;

        let pin = HW_BP_HOOK_HASHMAP.pin();
        pin.insert(target_address, sw_bp_hook);
        pin.get(&target_address)
            .map(|hook| hook.enable())
            .unwrap_or(Err(HookError::from(std::io::Error::last_os_error())))?;

        Ok(())
    }

    pub fn remove_hook(target_address: usize) -> Result<(), HookError> {
        let pin = HW_BP_HOOK_HASHMAP.pin();
        let hook = pin
            .get(&target_address)
            .ok_or(std::io::Error::last_os_error())?;

        hook.disable()?;
        pin.remove(&target_address);

        Ok(())
    }

    pub fn handle(&self, p: *mut EXCEPTION_POINTERS) -> Option<i32> {
        (self.handler)(p)
    }
}

impl HookBase for HardwareBreakpointHook {
    fn enable(&self) -> Result<(), HookError> {
        let target = self.target;
        let slot = self.slot;
        iterate_threads(Box::new(move |thd| Self::set_breakpoint(thd, target, slot)))
            .map_err(|e| HookError::from(e))
    }
    fn disable(&self) -> Result<(), HookError> {
        let target = self.target;
        let slot = self.slot;
        iterate_threads(Box::new(move |thd| {
            Self::remove_breakpoint(thd, target, slot)
        }))
        .map_err(|e| HookError::from(e))
    }

    fn handle(&self, p: *mut EXCEPTION_POINTERS) -> Option<i32> {
        (self.handler)(p)
    }

    fn add_hook(target_address: usize, handler: HookHandler) -> Result<(), HookError> {
        let mut slots = vec![
            HWBreakpointSlot::Slot0,
            HWBreakpointSlot::Slot1,
            HWBreakpointSlot::Slot2,
            HWBreakpointSlot::Slot3,
        ];

        HW_BP_HOOK_HASHMAP.pin().iter().for_each(|(_, v)| {
            if let Some(pos) = slots.iter().position(|&x| x == v.slot) {
                slots.remove(pos);
            }
        });

        if slots.is_empty() {
            return Err(HookError::from(std::io::Error::last_os_error()));
        }

        let slot = slots[0];

        Self::add_hook_at_slot(target_address, handler, slot)
    }

    fn remove_hook(target_address: usize) -> Result<(), HookError> {
        let pin = HW_BP_HOOK_HASHMAP.pin();
        let hook = pin
            .get(&target_address)
            .ok_or(std::io::Error::last_os_error())?;

        hook.disable()?;
        pin.remove(&target_address);

        Ok(())
    }

    fn handle_event(
        rip: usize,
        status: NTSTATUS,
        exception_info: *mut EXCEPTION_POINTERS,
    ) -> Option<i32> {
        match status {
            STATUS_SINGLE_STEP => {
                if let Some(hook) = HW_BP_HOOK_HASHMAP.pin().get(&rip) {
                    return Some(
                        hook.handle(exception_info)
                            .unwrap_or(veh_continue_hwbp(exception_info)),
                    );
                }

                None
            }
            _ => None,
        }
    }

    fn iter() -> Vec<usize> {
        HW_BP_HOOK_HASHMAP.pin().keys().copied().collect()
    }
}

impl Drop for HardwareBreakpointHook {
    fn drop(&mut self) {
        let result = self.disable();

        if let Err(result) = result {
            #[cfg(feature = "log")]
            log::error!("Failed to disable hardware breakpoint: {:#?}", result);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod hardware_breakpoint_tests {
    use crate::base_tests::BaseTest;
    use crate::hardware::{HWBreakpointSlot, HardwareBreakpointHook};
    use crate::hook_base::HookBase;
    use serial_test::serial;
    use std::ptr::null;
    use windows::core::imp::GetProcAddress;
    use windows::Win32::System::SystemInformation::{GetLocalTime, GetOsManufacturingMode};
    use windows::Win32::System::Threading::GetCurrentProcess;
    use windows_result::BOOL;

    static HW_BP_TEST_VALUE: std::sync::Mutex<i32> = std::sync::Mutex::new(0);

    struct HWBPHookTests;

    impl HWBPHookTests {
        fn add_multiple_hooks() {
            Self::reset_test_value();

            let _vm = Self::get_vm();
            let current = *HW_BP_TEST_VALUE.lock().unwrap();

            let result = HardwareBreakpointHook::add_hook(
                GetProcAddress as *const () as usize,
                |_exception_info| {
                    *HW_BP_TEST_VALUE.lock().unwrap() += 1;

                    None
                },
            );

            assert_eq!(result.is_ok(), true);

            let result = HardwareBreakpointHook::add_hook(
                GetCurrentProcess as *const () as usize,
                |_exception_info| {
                    *HW_BP_TEST_VALUE.lock().unwrap() += 1;

                    None
                },
            );

            assert_eq!(result.is_ok(), true);

            let result = HardwareBreakpointHook::add_hook(
                GetLocalTime as *const () as usize,
                |_exception_info| {
                    *HW_BP_TEST_VALUE.lock().unwrap() += 1;

                    None
                },
            );

            assert_eq!(result.is_ok(), true);

            let result = HardwareBreakpointHook::add_hook(
                GetOsManufacturingMode as *const () as usize,
                |_exception_info| {
                    *HW_BP_TEST_VALUE.lock().unwrap() += 1;

                    None
                },
            );

            assert_eq!(result.is_ok(), true);

            unsafe {
                GetProcAddress(0 as _, null());
                GetCurrentProcess();
                GetLocalTime();
                let mut b = BOOL::default();
                GetOsManufacturingMode(&mut b).unwrap();
            }

            assert_eq!(*HW_BP_TEST_VALUE.lock().unwrap(), current + 4);

            HardwareBreakpointHook::remove_all_hooks().unwrap();
        }

        fn drop_hook() {
            let _vm = HWBPHookTests::get_vm();
            HWBPHookTests::reset_test_value();
            let hook = HardwareBreakpointHook::create(
                Self::get_test_fn_address(),
                |_exception_info| {
                    *HW_BP_TEST_VALUE.lock().unwrap() += 1;

                    None
                },
                HWBreakpointSlot::Slot1,
            )
            .unwrap();

            hook.enable().unwrap();

            drop(hook);
        }
    }

    impl BaseTest for HWBPHookTests {
        fn reset_test_value() {
            HardwareBreakpointHook::remove_all_hooks().unwrap();
            *HW_BP_TEST_VALUE.lock().unwrap() = 0;
        }

        fn get_test_value() -> i32 {
            *HW_BP_TEST_VALUE.lock().unwrap()
        }

        fn set_test_value(value: i32) {
            *HW_BP_TEST_VALUE.lock().unwrap() = value;
        }

        fn add_hook() {
            let result =
                HardwareBreakpointHook::add_hook(Self::get_test_fn_address(), |_exception_info| {
                    *HW_BP_TEST_VALUE.lock().unwrap() += 1;

                    None
                });

            assert_eq!(result.is_ok(), true);
        }

        fn remove_hook() {
            let _result = HardwareBreakpointHook::remove_hook(Self::get_test_fn_address());
        }
    }
    #[test]
    #[serial]
    fn hook_three_times() {
        HWBPHookTests::hook_three_times()
    }

    #[test]
    #[serial]
    fn add_remove_add() {
        HWBPHookTests::add_remove_add()
    }

    #[test]
    #[serial]
    fn add_drop() {
        HWBPHookTests::add_drop()
    }

    #[test]
    #[serial]
    fn add_multiple_hooks() {
        HWBPHookTests::add_multiple_hooks()
    }

    #[test]
    #[serial]
    fn drop_hook() {
        HWBPHookTests::drop_hook()
    }
}
