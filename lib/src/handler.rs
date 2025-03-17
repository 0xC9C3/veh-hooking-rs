use crate::guard::GuardHook;
use crate::hardware::HardwareBreakpointHook;
use crate::hook_base::{veh_continue_search, HookBase};
use crate::manager::VEHManager;
use crate::software::SoftwareBreakpointHook;
use log::{debug, error};
use windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;

pub(crate) unsafe extern "system" fn veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        let exception_code = (*(*exception_info).ExceptionRecord).ExceptionCode;
        let rip = (*(*exception_info).ContextRecord).Rip as usize;
        #[cfg(feature = "log")]
        debug!(
            "VEH Handler: Exception code: {:#X}, RIP: {:#X}",
            exception_code.0, rip
        );

        match VEHManager::trigger_callbacks(exception_info) {
            Ok(i) => {
                if let Some(i) = i {
                    return i;
                }
            }
            Err(e) => {
                #[cfg(feature = "log")]
                error!("Failed to trigger VEH callbacks: {:#?}", e);
            }
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
