use log::{info, LevelFilter};
use veh_hooking_rs::manager::VEHManager;

fn main() {
    init_env_logger();
    hw_bp_with_veh_cb()
}

fn init_env_logger() {
    env_logger::Builder::from_default_env()
        .format_timestamp(None)
        .format_module_path(false)
        .filter_level(LevelFilter::Info)
        .init();
}

#[allow(dead_code)]
fn hw_bp_with_veh_cb() {
    let vm = VEHManager::new().expect("Failed to initialize VMM");
    vm.add_callback(1, |_p| {
        info!("Callback triggered!");

        None
    })
    .expect("Failed to add callback");
    let result = vm.add_hardware_breakpoint_hook(
        std::thread::sleep as *const () as usize,
        |_exception_info| {
            info!("Hooked!");

            None
        },
    );

    info!("Create result! {:#?}", result);

    info!("Begin loop");
    loop {
        info!("Outer tick");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[allow(dead_code)]
fn hw_bp() {
    let vm = VEHManager::new().expect("Failed to initialize VMM");
    let result = vm.add_hardware_breakpoint_hook(
        std::thread::sleep as *const () as usize,
        |_exception_info| {
            info!("Hooked!");

            None
        },
    );

    info!("Create result! {:#?}", result);

    info!("Begin loop");
    loop {
        info!("Outer tick");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[allow(dead_code)]
fn sw_bp() {
    let vm = VEHManager::new().expect("Failed to initialize VMM");
    let result = vm.add_software_breakpoint_hook(
        std::thread::sleep as *const () as usize,
        |_exception_info| {
            info!("Hooked!");

            None
        },
    );

    info!("Create result! {:#?}", result);

    info!("Begin loop");
    loop {
        info!("Outer tick");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[allow(dead_code)]
fn guard_bp() {
    let vm = VEHManager::new().expect("Failed to initialize VMM");
    let result = vm.add_guard_hook(
        std::thread::sleep as *const () as usize,
        |_exception_info| {
            info!("Hooked!");

            None
        },
    );

    info!("Create result! {:#?}", result);

    info!("Begin loop");
    loop {
        info!("Outer tick");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
