use crate::guard::GuardHook;
use crate::hardware::HardwareBreakpointHook;
use crate::hook_base::{veh_continue_search, HookBase};
use crate::manager::VEHManager;
use crate::software::SoftwareBreakpointHook;
use windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;

pub(crate) unsafe extern "system" fn veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        let exception_code = (*(*exception_info).ExceptionRecord).ExceptionCode;
        let rip = (*(*exception_info).ContextRecord).Rip as usize;

        if let Some(result) = VEHManager::trigger_callbacks(exception_info) {
            return result;
        }

        if let Some(result) =
            HardwareBreakpointHook::handle_event(rip, exception_code, exception_info)
        {
            return result;
        }

        if let Some(result) =
            SoftwareBreakpointHook::handle_event(rip, exception_code, exception_info)
        {
            return result;
        }

        if let Some(result) = GuardHook::handle_event(rip, exception_code, exception_info) {
            return result;
        }

        veh_continue_search()
    }
}
