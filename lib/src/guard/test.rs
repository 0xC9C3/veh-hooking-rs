/*#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod guard_tests {
    use crate::base_tests::BaseTest;
    use crate::guard::GuardHook;
    use crate::hook_base::HookBase;
    use serial_test::serial;

    static GUARD_TEST_VALUE: std::sync::Mutex<i32> = std::sync::Mutex::new(0);

    struct GuardHookTests;

    impl GuardHookTests {
        fn drop() {
            let _vm = GuardHookTests::get_vm();
            GuardHookTests::reset_test_value();
            let hook = GuardHook::create(Self::get_test_fn_address(), |_exception_info| {
                *GUARD_TEST_VALUE.lock().unwrap() += 1;

                None
            })
            .unwrap();

            hook.enable().unwrap();

            drop(hook);

            Self::call_test_fn()
        }
    }

    impl BaseTest for GuardHookTests {
        fn reset_test_value() {
            GuardHook::remove_all_hooks().unwrap();
            *GUARD_TEST_VALUE.lock().unwrap() = 0;
        }

        fn get_test_value() -> i32 {
            *GUARD_TEST_VALUE.lock().unwrap()
        }

        fn set_test_value(value: i32) {
            *GUARD_TEST_VALUE.lock().unwrap() = value;
        }

        fn add_hook() {
            let result = GuardHook::add_hook(Self::get_test_fn_address(), |_exception_info| {
                *GUARD_TEST_VALUE.lock().unwrap() += 1;

                None
            });

            assert_eq!(result.is_ok(), true);
        }

        fn remove_hook() {
            let _result = GuardHook::remove_hook(Self::get_test_fn_address());
        }
    }

    #[test]
    #[serial]
    fn hook_three_times() {
        GuardHookTests::hook_three_times()
    }

    #[test]
    #[serial]
    fn add_remove_add() {
        GuardHookTests::add_remove_add()
    }

    #[test]
    #[serial]
    fn add_drop() {
        GuardHookTests::add_drop()
    }

    #[test]
    #[serial]
    fn test_drop() {
        GuardHookTests::drop();
    }
}*/
