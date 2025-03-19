#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test;

use crate::hook_base::HookError::{HookNotFound, NoEmptySlot, UnknownHardwareBreakpointSlot};
use crate::hook_base::{veh_continue_hwbp, HookBase, HookError};
use crate::manager::HookHandler;
use crate::util::{iterate_threads, os_bitness};
use papaya::HashMap;
use std::sync::LazyLock;
use windows::Win32::Foundation::{CloseHandle, NTSTATUS, STATUS_SINGLE_STEP};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT_DEBUG_REGISTERS_AMD64,
    CONTEXT_DEBUG_REGISTERS_X86, EXCEPTION_POINTERS,
};
use windows::Win32::System::Threading::{GetCurrentThreadId, OpenThread, THREAD_ALL_ACCESS};

pub(crate) static HW_BP_HOOK_HASHMAP: LazyLock<
    HashMap<u32, HashMap<usize, HardwareBreakpointHook>>,
> = LazyLock::new(|| HashMap::new());

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

    pub fn add_hook_with_thread_id(
        thread_id: u32,
        target_address: usize,
        handler: HookHandler,
    ) -> Result<(), HookError> {
        let slot = Self::get_free_slot_for_thread(thread_id)?;
        HardwareBreakpointHook::add_hook_at_slot_for_thread(
            target_address,
            handler,
            slot,
            thread_id,
        )
    }

    pub fn enable_for_thread(&self, thread_id: u32) -> Result<(), HookError> {
        let thread_handle = Self::get_thread_handle(thread_id)?;
        Self::set_breakpoint(thread_handle, self.target, self.slot)?;
        Self::close_thread_handle(thread_handle)
    }

    pub fn disable_for_thread(&self, thread_id: u32) -> Result<(), HookError> {
        let thread_handle = Self::get_thread_handle(thread_id)?;
        Self::remove_breakpoint(thread_handle, self.target, self.slot)?;
        Self::close_thread_handle(thread_handle)
    }

    fn get_thread_handle(thread_id: u32) -> Result<windows::Win32::Foundation::HANDLE, HookError> {
        Ok(unsafe { OpenThread(THREAD_ALL_ACCESS, false, thread_id)? })
    }

    fn close_thread_handle(
        thread_handle: windows::Win32::Foundation::HANDLE,
    ) -> Result<(), HookError> {
        Ok(unsafe { CloseHandle(thread_handle)? })
    }

    pub fn enable_for_all_threads(&self) -> Result<(), HookError> {
        let target = self.target;
        let slot = self.slot;
        iterate_threads(Box::new(move |thread_id| {
            let thread_handle = unsafe { OpenThread(THREAD_ALL_ACCESS, false, thread_id) }?;
            Self::set_breakpoint(thread_handle, target, slot)?;
            Ok(unsafe { CloseHandle(thread_handle) }?)
        }))
        .map_err(|e| HookError::from(e))
    }

    pub fn disable_for_all_threads(&self) -> Result<(), HookError> {
        let target = self.target;
        let slot = self.slot;
        iterate_threads(Box::new(move |thread_id| {
            let thread_handle = unsafe { OpenThread(THREAD_ALL_ACCESS, false, thread_id) }?;
            Self::remove_breakpoint(thread_handle, target, slot)?;
            Ok(unsafe { CloseHandle(thread_handle) }?)
        }))
        .map_err(|e| HookError::from(e))
    }

    pub fn get_free_slot_for_thread(thread_id: u32) -> Result<HWBreakpointSlot, HookError> {
        let mut slots = vec![
            HWBreakpointSlot::Slot0,
            HWBreakpointSlot::Slot1,
            HWBreakpointSlot::Slot2,
            HWBreakpointSlot::Slot3,
        ];

        let pin = HW_BP_HOOK_HASHMAP.pin();
        let t = pin.get(&thread_id);

        if t.is_none() {
            return Ok(HWBreakpointSlot::Slot0);
        }

        t.unwrap().pin().iter().for_each(|(_, v)| {
            if let Some(pos) = slots.iter().position(|&x| x == v.slot) {
                slots.remove(pos);
            }
        });

        if slots.is_empty() {
            return Err(NoEmptySlot);
        }

        let slot = slots[0];

        Ok(slot)
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

    pub fn add_hook_at_slot(
        target_address: usize,
        handler: HookHandler,
        breakpoint_slot: HWBreakpointSlot,
    ) -> Result<(), HookError> {
        iterate_threads(Box::new(move |thread_id| {
            HardwareBreakpointHook::add_hook_at_slot_for_thread(
                target_address,
                handler,
                breakpoint_slot,
                thread_id,
            )
        }))
    }

    pub fn add_hook_at_slot_for_thread(
        target_address: usize,
        handler: HookHandler,
        breakpoint_slot: HWBreakpointSlot,
        thread_id: u32,
    ) -> Result<(), HookError> {
        let sw_bp_hook = HardwareBreakpointHook::create(target_address, handler, breakpoint_slot)?;

        let pin = HW_BP_HOOK_HASHMAP.pin();
        pin.get(&thread_id)
            .unwrap_or_else(|| {
                pin.insert(thread_id, HashMap::new());
                pin.get(&thread_id).unwrap()
            })
            .pin()
            .insert(target_address, sw_bp_hook);

        pin.get(&thread_id)
            .unwrap()
            .pin()
            .get(&target_address)
            .map(|hook| hook.enable_for_thread(thread_id))
            .unwrap_or(Err(HookNotFound))?;

        Ok(())
    }

    pub fn remove_hook_for_thread(target_address: usize, thread_id: u32) -> Result<(), HookError> {
        let pin = HW_BP_HOOK_HASHMAP.pin();
        let thread_hook = pin.get(&thread_id);
        if thread_hook.is_none() {
            return Ok(());
        }
        let thread_hook = thread_hook.unwrap().pin();

        let hook = thread_hook.get(&target_address);
        if hook.is_none() {
            return Ok(());
        }
        let hook = hook.unwrap();

        hook.disable_for_thread(thread_id)?;

        pin.get(&thread_id).unwrap().pin().remove(&target_address);

        Ok(())
    }

    pub fn handle(&self, p: *mut EXCEPTION_POINTERS) -> Option<i32> {
        (self.handler)(p)
    }
}

impl HookBase for HardwareBreakpointHook {
    fn enable(&self) -> Result<(), HookError> {
        self.enable_for_all_threads()
    }
    fn disable(&self) -> Result<(), HookError> {
        self.disable_for_all_threads()
    }

    fn handle(&self, p: *mut EXCEPTION_POINTERS) -> Option<i32> {
        (self.handler)(p)
    }

    fn add_hook(target_address: usize, handler: HookHandler) -> Result<(), HookError> {
        iterate_threads(Box::new(move |thread_id| {
            let slot = HardwareBreakpointHook::get_free_slot_for_thread(thread_id)?;
            HardwareBreakpointHook::add_hook_at_slot_for_thread(
                target_address,
                handler,
                slot,
                thread_id,
            )
        }))
    }

    fn remove_hook(target_address: usize) -> Result<(), HookError> {
        iterate_threads(Box::new(move |thread_id| {
            HardwareBreakpointHook::remove_hook_for_thread(target_address, thread_id)
        }))
    }

    fn handle_event(
        rip: usize,
        status: NTSTATUS,
        exception_info: *mut EXCEPTION_POINTERS,
    ) -> Option<i32> {
        match status {
            STATUS_SINGLE_STEP => {
                let thread_id = unsafe { GetCurrentThreadId() };
                if let Some(hook) = HW_BP_HOOK_HASHMAP.pin().get(&thread_id)?.pin().get(&rip) {
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
        let pin = HW_BP_HOOK_HASHMAP.pin();
        let mut result = Vec::new();

        for (_, v) in pin.iter() {
            for (_, hook) in v.pin().iter() {
                result.push(hook.target);
            }
        }

        result.sort();
        result.dedup();

        result
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
