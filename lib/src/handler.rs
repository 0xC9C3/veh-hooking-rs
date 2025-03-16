use crate::guard::GUARD_HOOK_HASHMAP;
use crate::hardware::HW_BP_HOOK_HASHMAP;
use crate::manager::{veh_continue, veh_continue_hwbp, veh_continue_search, veh_continue_step};
use crate::software::SW_BP_HOOK_HASHMAP;
use windows::Win32::Foundation::{
    EXCEPTION_BREAKPOINT, STATUS_GUARD_PAGE_VIOLATION, STATUS_SINGLE_STEP,
};
use windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;

pub(crate) unsafe extern "system" fn veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        let exception_code = (*(*exception_info).ExceptionRecord).ExceptionCode;

        match exception_code {
            EXCEPTION_BREAKPOINT => handle_breakpoint(exception_info),
            STATUS_GUARD_PAGE_VIOLATION => handle_page_guard_violation(exception_info),
            STATUS_SINGLE_STEP => handle_single_step(exception_info),
            _ => veh_continue_search(),
        }
    }
}

fn handle_page_guard_violation(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let rip = unsafe { (*(*exception_info).ContextRecord).Rip as usize };
    let result = GUARD_HOOK_HASHMAP
        .pin()
        .get(&rip)
        .map(|hook| hook.handle(exception_info))
        .unwrap_or(None);

    if let Some(result) = result {
        return result;
    }

    veh_continue_step(exception_info)
}

fn handle_breakpoint(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let rip = unsafe { (*(*exception_info).ContextRecord).Rip as usize };
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
        return result;
    }

    veh_continue_step(exception_info)
}

fn handle_single_step(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let rip = unsafe { (*(*exception_info).ContextRecord).Rip as usize };
    if let Some(hook) = HW_BP_HOOK_HASHMAP.pin().get(&rip) {
        return hook
            .handle(exception_info)
            .unwrap_or(veh_continue_hwbp(exception_info));
    }

    if let Some(hook) = SW_BP_HOOK_HASHMAP.pin().get(&rip) {
        hook.enable().expect("Failed to reapply hook");
        return veh_continue();
    }

    GUARD_HOOK_HASHMAP.pin().iter().for_each(|(_, hook)| {
        hook.reapply_hook().expect("Failed to reapply hook");
    });

    veh_continue()
}
