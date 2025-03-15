use iced_x86::{Decoder, DecoderOptions};
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

    let result = unsafe {
        VirtualProtect(
            target as *mut _,
            size_of::<u8>(),
            protection,
            &mut old_protection,
        )
    };

    if result.is_err() {
        return Err(std::io::Error::last_os_error());
    }

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

pub fn iterate_threads(
    callback: Box<dyn Fn(windows::Win32::Foundation::HANDLE) -> Result<(), std::io::Error>>,
) -> Result<(), std::io::Error> {
    let pid = unsafe { GetCurrentProcessId() };
    let h = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if h.is_err() {
        return Err(std::io::Error::last_os_error());
    }
    let h = h.unwrap();

    let mut te = THREADENTRY32::default();
    te.dwSize = size_of::<THREADENTRY32>() as u32;
    let thread32_first = unsafe { Thread32First(h, &mut te) };
    if thread32_first.is_err() {
        return Err(std::io::Error::last_os_error());
    }

    loop {
        if te.th32OwnerProcessID == pid {
            let thd = unsafe { OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID) };
            if thd.is_err() {
                return Err(std::io::Error::last_os_error());
            }

            let thd = thd.unwrap();

            callback(thd)?;

            let result = unsafe { CloseHandle(thd) };

            if result.is_err() {
                return Err(std::io::Error::last_os_error());
            }
        }

        te.dwSize = size_of::<THREADENTRY32>() as u32;
        let thread32_next = unsafe { Thread32Next(h, &mut te) };
        if thread32_next.is_err() {
            if thread32_next.err().unwrap().code().0 as u32 == 0x80070012 {
                return Ok(());
            }
            return Err(std::io::Error::last_os_error());
        }
    }
}
