#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod software_breakpoint_tests {
    use crate::base_tests::BaseTest;
    use crate::hook_base::HookBase;
    use crate::software::SoftwareBreakpointHook;
    use serial_test::serial;

    static SW_BP_TEST_VALUE: std::sync::Mutex<i32> = std::sync::Mutex::new(0);

    struct SWBPHookTests;

    impl SWBPHookTests {
        fn drop_hook() {
            let _vm = SWBPHookTests::get_vm();
            SWBPHookTests::reset_test_value();
            let hook =
                SoftwareBreakpointHook::create(Self::get_test_fn_address(), |_exception_info| {
                    *SW_BP_TEST_VALUE.lock().unwrap() += 1;

                    None
                })
                .unwrap();

            hook.enable().unwrap();

            drop(hook);
        }
    }

    impl BaseTest for SWBPHookTests {
        fn reset_test_value() {
            SoftwareBreakpointHook::remove_all_hooks().unwrap();
            *SW_BP_TEST_VALUE.lock().unwrap() = 0;
        }

        fn get_test_value() -> i32 {
            *SW_BP_TEST_VALUE.lock().unwrap()
        }

        fn set_test_value(value: i32) {
            *SW_BP_TEST_VALUE.lock().unwrap() = value;
        }

        fn add_hook() {
            let result =
                SoftwareBreakpointHook::add_hook(Self::get_test_fn_address(), |_exception_info| {
                    *SW_BP_TEST_VALUE.lock().unwrap() += 1;

                    None
                });

            assert_eq!(result.is_ok(), true);
        }

        fn remove_hook() {
            let _result = SoftwareBreakpointHook::remove_hook(Self::get_test_fn_address());
        }
    }

    #[test]
    #[serial]
    fn hook_three_times() {
        SWBPHookTests::hook_three_times()
    }

    #[test]
    #[serial]
    fn add_remove_add() {
        SWBPHookTests::add_remove_add()
    }

    #[test]
    #[serial]
    fn add_drop() {
        SWBPHookTests::add_drop()
    }

    #[test]
    #[serial]
    fn drop_hook() {
        SWBPHookTests::drop_hook()
    }
}
