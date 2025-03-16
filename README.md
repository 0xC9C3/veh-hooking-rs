# veh-hooking-rs

[![Crates.io Version](https://img.shields.io/crates/v/veh-hooking-rs)](https://crates.io/crates/veh-hooking-rs/)
![CI workflow](https://github.com/0xC9C3/veh-hooking-rs/actions/workflows/ci.yml/badge.svg?branch=main)

A library for creating hooks using VEH (Vectored Exception Handling) on Windows.

There are currently three types of hooks implemented:

- Hardware breakpoints
    - Hooks using hardware breakpoints are the fastest, but there are only 4 hardware breakpoints available.
- Software breakpoints
    - Hooks using software breakpoints are slower than hardware breakpoints, but there are no limits on the number of
      hooks. Software breakpoints are implemented using the `INT3` instruction and will write to the memory.
- Guard page hooks
    - Guard page hooks are the slowest. Guard page hooks are implemented by setting the
      memory protection of the page to `PAGE_GUARD` and then handling the exception that is thrown when the page is
      accessed. These are the slowest, since they trigger an exception on every access to the page. However, they are
      useful for hooking memory that is not executed frequently.

## Example

There are two ways to use this library, the High level API and the Low level API. The advantage of the High level API is
that the VEHManager will handle the initialization and cleanup of the VEH handler.

Example using the High level API:

Hook the `std::thread::sleep` function using a hardware breakpoint:

```rust
use veh_hooking_rs::manager::VEHManager;

fn main() {
    let vm = VEHManager::new().expect("Failed to initialize VMM");
    let result = vm.add_hardware_breakpoint_hook(
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
```

Example using the Low level API:

Hook the `std::thread::sleep` function using a hardware breakpoint:

```rust
use veh_hooking_rs::hardware_breakpoint::HardwareBreakpointHook;
use veh_hooking_rs::hook_base::HookBase;

fn main() {
    // ... create a vectored exception handler beforehand
    let result = HardwareBreakpointHook::add_hook(
        std::thread::sleep as *const () as usize,
        |_exception_info| {
            println!("Hooked!");
            None
        },
        HWBreakpointSlot::Slot1,
    );

    println!("Create result! {:#?}", result);

    println!("Begin loop");
    loop {
        println!("Outer tick");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
```

### HookHandler

HookHandler is a closure that takes a `*mut EXCEPTION_POINTERS` as an argument and returns an `Option<i32>`.
If `None` is returned, the hook will continue execution. If `Some` is returned, the hook will return the value.
This is useful for manually handling the NTSTATUS code returned by the Vectored Exception Handler in case you i.e. want
to pass the exception to the next handler.

### Callback whenever the VEH is triggered

For even more control, you can use the `VEHManager::add_callback` method to add callbacks that will be called whenever
the VEH is triggered.

```rust
use veh_hooking_rs::manager::VEHManager;

fn main() {
    let vm = VEHManager::new().expect("Failed to initialize VMM");
    vm.add_callback(1, |_p| {
        println!("Callback triggered!");

        None
    });
    let result = vm.add_hardware_breakpoint_hook(
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
```

## Versioning

This project is still in the early stages of development, so the API may change frequently. 