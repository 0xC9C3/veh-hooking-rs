use crate::manager::VEHManager;

static TEST_FN_ADDRESS: std::sync::Mutex<usize> = std::sync::Mutex::new(0);

pub trait BaseTest {
    fn reset_test_value();
    fn get_test_value() -> i32;
    #[allow(unused)]
    fn set_test_value(value: i32);
    fn add_hook();
    fn remove_hook();
    fn get_vm() -> VEHManager {
        VEHManager::new().unwrap()
    }
    fn hook_three_times() {
        Self::reset_test_value();

        let _vm = Self::get_vm();
        let mut current = Self::get_test_value();

        Self::add_hook();

        for _ in 0..3 {
            assert_eq!(Self::get_test_value(), current);

            Self::call_test_fn();

            current += 1;

            assert_eq!(Self::get_test_value(), current);
        }

        Self::remove_hook();
    }

    fn add_remove_add() {
        Self::reset_test_value();

        let _vm = Self::get_vm();
        let current = Self::get_test_value();

        Self::add_hook();

        Self::call_test_fn();
        assert_eq!(Self::get_test_value(), current + 1);

        Self::remove_hook();

        Self::call_test_fn();
        assert_eq!(Self::get_test_value(), current + 1);

        Self::add_hook();

        Self::call_test_fn();

        assert_eq!(Self::get_test_value(), current + 2);

        Self::remove_hook();
    }

    fn add_drop() {
        Self::reset_test_value();

        let vm = Self::get_vm();
        let current = Self::get_test_value();

        Self::add_hook();

        Self::call_test_fn();
        assert_eq!(Self::get_test_value(), current + 1);

        drop(vm);

        Self::call_test_fn();
        assert_eq!(Self::get_test_value(), current + 1);

        Self::remove_hook();
    }

    fn init_test_fn() {
        *TEST_FN_ADDRESS.lock().unwrap() = test_fn as *const () as usize;
    }

    fn call_test_fn() {
        if *TEST_FN_ADDRESS.lock().unwrap() == 0 {
            Self::init_test_fn();
        }

        test_fn();
    }

    fn get_test_fn_address() -> usize {
        if *TEST_FN_ADDRESS.lock().unwrap() == 0 {
            Self::init_test_fn();
        }
        //test_fn as *const () as usize
        *TEST_FN_ADDRESS.lock().unwrap()
    }
}

fn test_fn() -> i32 {
    0
}
