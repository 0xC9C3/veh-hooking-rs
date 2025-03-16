use crate::manager::VEHManager;
use std::ptr::null;
use windows::core::imp::GetProcAddress;

pub trait BaseTest {
    fn reset_test_value();
    fn get_test_value() -> i32;
    #[allow(unused)]
    fn set_test_value(value: i32);
    fn add_get_proc_address_hook();
    fn remove_get_proc_address_hook();
    fn get_vm() -> VEHManager {
        VEHManager::new().unwrap()
    }
    fn hook_three_times() {
        Self::reset_test_value();

        let _vm = Self::get_vm();
        let mut current = Self::get_test_value();

        Self::add_get_proc_address_hook();

        for _ in 0..3 {
            assert_eq!(Self::get_test_value(), current);

            unsafe {
                GetProcAddress(0 as _, null());
            }
            assert_eq!(Self::get_test_value(), current + 1);

            current += 1;
        }

        Self::remove_get_proc_address_hook();
    }

    fn add_remove_add() {
        Self::reset_test_value();

        let _vm = Self::get_vm();
        let current = Self::get_test_value();

        Self::add_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(Self::get_test_value(), current + 1);

        Self::remove_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(Self::get_test_value(), current + 1);

        Self::add_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }

        assert_eq!(Self::get_test_value(), current + 2);

        Self::remove_get_proc_address_hook();
    }

    fn add_drop() {
        Self::reset_test_value();

        let vm = Self::get_vm();
        let current = Self::get_test_value();

        Self::add_get_proc_address_hook();

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(Self::get_test_value(), current + 1);

        drop(vm);

        unsafe {
            GetProcAddress(0 as _, null());
        }
        assert_eq!(Self::get_test_value(), current + 1);
    }
}
