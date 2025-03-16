use veh_hooking_rs::hardware::HWBreakpointSlot;
use veh_hooking_rs::manager::VEHManager;

fn main() {
    sw_bp()
}

#[allow(dead_code)]
fn hw_bp() {
    let vm = VEHManager::new().expect("Failed to initialize VMM");
    let result = vm.add_hardware_hook(
        std::thread::sleep as *const () as usize,
        |_exception_info| {
            println!("Hooked!");

            None
        },
        HWBreakpointSlot::Slot3,
    );

    println!("Create result! {:#?}", result);

    println!("Begin loop");
    loop {
        println!("Outer tick");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[allow(dead_code)]
fn sw_bp() {
    let vm = VEHManager::new().expect("Failed to initialize VMM");
    let result = vm.add_software_hook(
        std::thread::sleep as *const () as usize,
        |_exception_info| {
            println!("Hooked!");

            None
        },
    );

    println!("Create result! {:#?}", result);

    println!("Begin loop");
    loop {
        println!("Outer tick");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[allow(dead_code)]
fn guard_bp() {
    let vm = VEHManager::new().expect("Failed to initialize VMM");
    let result = vm.add_guard_hook(
        std::thread::sleep as *const () as usize,
        |_exception_info| {
            println!("Hooked!");

            None
        },
    );

    println!("Create result! {:#?}", result);

    println!("Begin loop");
    loop {
        println!("Outer tick");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
