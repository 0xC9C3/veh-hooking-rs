use crate::hook_base::HookError;
use iced_x86::{Decoder, DecoderOptions};
use windows::Wdk::System::Threading::{NtQueryInformationThread, ThreadQuerySetWin32StartAddress};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Memory::{
    VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};
use windows::Win32::System::Threading::{GetCurrentProcessId, OpenThread, THREAD_ALL_ACCESS};

pub fn virtual_protect(
    target: usize,
    protection: PAGE_PROTECTION_FLAGS,
) -> Result<PAGE_PROTECTION_FLAGS, std::io::Error> {
    let mut old_protection = PAGE_PROTECTION_FLAGS::default();

    unsafe {
        VirtualProtect(
            target as *mut _,
            size_of::<u8>(),
            protection,
            &mut old_protection,
        )
    }?;

    Ok(old_protection)
}

pub fn virtual_query(target: usize) -> Result<PAGE_PROTECTION_FLAGS, std::io::Error> {
    let mut memory_info: MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION::default();
    let result = unsafe {
        VirtualQuery(
            Some(target as *const _),
            &mut memory_info,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };

    if result == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(memory_info.Protect)
}

pub fn get_next_instruction_offset(target: usize) -> Result<usize, std::io::Error> {
    let ptr = target as *const u8;
    let mut decoder = Decoder::new(
        os_bitness(),
        unsafe { std::slice::from_raw_parts(ptr, 255) },
        DecoderOptions::NONE,
    );
    let inst = decoder.decode();

    Ok(target + inst.len())
}

// adopted via https://github.com/forbjok/rust-bitness/blob/master/src/windows.rs
pub fn os_bitness() -> u32 {
    use std::mem;

    // Allocate zeroed SYSTEM_INFO struct
    let mut system_info: SYSTEM_INFO = unsafe { mem::zeroed() };

    // Retrieve native system info from Windows API
    unsafe { GetNativeSystemInfo(&mut system_info) };

    unsafe {
        match system_info.Anonymous.Anonymous.wProcessorArchitecture {
            windows::Win32::System::SystemInformation::PROCESSOR_ARCHITECTURE_INTEL => 32,
            windows::Win32::System::SystemInformation::PROCESSOR_ARCHITECTURE_AMD64 => 64,
            _ => 0,
        }
    }
}

static NO_MORE_FILES: u32 = 0x80070012;
pub fn iterate_threads<F>(mut callback: F) -> Result<(), HookError>
where
    F: FnMut(u32) -> Result<(), HookError>,
{
    let pid = unsafe { GetCurrentProcessId() };
    let h = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }?;

    let mut te = THREADENTRY32::default();
    te.dwSize = size_of::<THREADENTRY32>() as u32;
    unsafe { Thread32First(h, &mut te) }?;

    loop {
        if te.th32OwnerProcessID == pid {
            callback(te.th32ThreadID)?;
        }

        te.dwSize = size_of::<THREADENTRY32>() as u32;
        let thread32_next = unsafe { Thread32Next(h, &mut te) };
        if let Err(e) = thread32_next {
            if e.code().0 as u32 == NO_MORE_FILES {
                return Ok(());
            }
            return Err(HookError::from(e));
        }
    }
}

pub fn find_threads_by_entry_point(entry_point: usize) -> Result<Vec<u32>, HookError> {
    let mut threads = Vec::new();

    let get_fn = |tid| {
        let thread_handle = unsafe { OpenThread(THREAD_ALL_ACCESS, false, tid) }?;

        let start_address: usize = 0;
        let result = unsafe {
            NtQueryInformationThread(
                thread_handle,
                ThreadQuerySetWin32StartAddress,
                &start_address as *const _ as *mut _,
                size_of::<usize>() as u32,
                std::ptr::null_mut(),
            )
        };

        unsafe { CloseHandle(thread_handle) }?;

        if result.is_err() {
            return Err(HookError::from(std::io::Error::last_os_error()));
        }

        if start_address == entry_point {
            threads.push(tid);
        }

        Ok(())
    };

    iterate_threads(Box::new(get_fn))?;

    Ok(threads)
}
