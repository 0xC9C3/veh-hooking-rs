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
    use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentThreadId};
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

        fn add_multi_thread_hooks() {
            Self::reset_test_value();

            let _vm = Self::get_vm();
            let spawn_fn = || {
                let result = HardwareBreakpointHook::add_hook_with_thread_id(
                    unsafe { GetCurrentThreadId() },
                    GetProcAddress as *const () as usize,
                    |_exception_info| {
                        *HW_BP_TEST_VALUE.lock().unwrap() += 1;
                        None
                    },
                );

                assert_eq!(result.is_ok(), true);

                unsafe {
                    GetProcAddress(0 as _, null());
                }
            };

            let thread1 = std::thread::spawn(spawn_fn);

            let thread2 = std::thread::spawn(spawn_fn);

            // wait for all threads to finish
            thread1.join().unwrap();
            thread2.join().unwrap();

            assert_eq!(*HW_BP_TEST_VALUE.lock().unwrap(), 2);
        }

        fn add_multi_thread_hooks_at_same_slot() {
            Self::reset_test_value();

            let _vm = Self::get_vm();

            let spawn_fn = || {
                let result = HardwareBreakpointHook::add_hook_at_slot_for_thread(
                    GetProcAddress as *const () as usize,
                    |_exception_info| {
                        *HW_BP_TEST_VALUE.lock().unwrap() += 1;
                        None
                    },
                    HWBreakpointSlot::Slot0,
                    unsafe { GetCurrentThreadId() },
                );

                assert_eq!(result.is_ok(), true);

                unsafe {
                    GetProcAddress(0 as _, null());
                }
            };

            let mut threads = Vec::new();
            for _ in 0..10 {
                threads.push(std::thread::spawn(spawn_fn));
            }

            for thread in threads {
                thread.join().unwrap();
            }

            assert_eq!(*HW_BP_TEST_VALUE.lock().unwrap(), 10);
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
        HWBPHookTests::hook_three_times();
    }

    #[test]
    #[serial]
    fn add_remove_add() {
        HWBPHookTests::add_remove_add();
    }

    #[test]
    #[serial]
    fn add_drop() {
        HWBPHookTests::add_drop()
    }

    #[test]
    #[serial]
    fn add_multiple_hooks() {
        HWBPHookTests::add_multiple_hooks();
    }

    #[test]
    #[serial]
    fn drop_hook() {
        HWBPHookTests::drop_hook();
    }

    #[test]
    #[serial]
    fn add_multi_thread_hooks() {
        HWBPHookTests::add_multi_thread_hooks();
    }

    #[test]
    #[serial]
    fn add_multi_thread_hooks_at_same_slot() {
        HWBPHookTests::add_multi_thread_hooks_at_same_slot();
    }
}
