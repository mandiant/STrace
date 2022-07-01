#![feature(link_llvm_intrinsics)]
#![feature(asm)]
#![feature(naked_functions)]
use strace_core::{self, ModuleRef, Runtime, RuntimeValue};

static mut WasmModule: Option<ModuleRef> = None;
static mut WasmRuntime: Option<Runtime> = None;

fn log(msg: &str) {
    println!("{}", msg);
}

pub fn mockStpCallbackEntry(probeId: u64) {
    // retrieve global wasm objects
    let main = unsafe { WasmModule.as_ref().clone().unwrap() };
    let runtime = unsafe { WasmRuntime.as_mut().unwrap() };

    // copy argument array from our memory space, to wasm memory space
    let wasm_arg_array_ptr = strace_core::alloc_wasm(main.clone(), runtime, 8 * 8);

    // invoke script callback entry export
    main.invoke_export(
        "StpCallbackEntry",
        &[
            RuntimeValue::I64(1337),
            RuntimeValue::I32(1),
            RuntimeValue::I32(0),
            RuntimeValue::I32(wasm_arg_array_ptr),
            RuntimeValue::I32(0),
            RuntimeValue::I32(wasm_arg_array_ptr),
        ],
        runtime,
    )
    .expect("Failed test StpCallbackEntry");

    strace_core::dealloc_wasm(main.clone(), runtime, wasm_arg_array_ptr, 8 * 8);
}

pub fn mock_KeSetSystemServiceCallback(
    syscallName: *const char,
    isEntry: bool,
    callback: u64,
    probeId: u64,
) -> u64 {
    return 0;
}

pub fn set_callback(syscallName: &str, isEntry: bool, probeId: u64) -> bool {
    // TODO:
    let nullSyscallName = format!("{}\x00", syscallName);
    return mock_KeSetSystemServiceCallback(
        nullSyscallName.as_ptr() as *const char,
        isEntry,
        0,
        probeId,
    ) != 0;
}

fn main() {
    println!("Starting main...");

    // TODO, does nothing
    let (main, mut runtime) = strace_core::loadStraceWasmModule(
        include_bytes!(
            "..\\..\\WasmScript\\target\\wasm32-unknown-unknown\\debug\\wasm_script.wasm"
        ),
        &vec![
            "alloc",
            "strace_initialize",
            "StpCallbackEntry",
            "StpCallbackReturn",
        ][..],
        log,
        set_callback,
    )
    .expect("failed to wasm module");

    main.invoke_export("strace_initialize", &[], &mut runtime)
        .expect("Failed STrace wasm initialization");

    unsafe {
        WasmModule = Some(main);
        WasmRuntime = Some(runtime);
    };

    // 8 pointer sized slots
    let wasm_arg_array_ptr = strace_core::alloc_wasm(
        unsafe { WasmModule.clone().unwrap() },
        unsafe { WasmRuntime.as_mut().unwrap() },
        8 * 8,
    );
    let fake_arg: u64 = 1338;
    let fake_arg_ptr = &fake_arg as *const u64 as i64;
    let _ = unsafe { WasmRuntime.as_mut().unwrap() }
        .memory
        .set_value(wasm_arg_array_ptr as u32, fake_arg_ptr);

    println!("fakeArgPtr: {}", fake_arg_ptr);
    unsafe { WasmModule.clone().unwrap() }
        .invoke_export(
            "StpCallbackEntry",
            &[
                RuntimeValue::I64(1337),
                RuntimeValue::I32(1),
                RuntimeValue::I32(1),
                RuntimeValue::I32(wasm_arg_array_ptr),
                RuntimeValue::I32(1),
                RuntimeValue::I32(wasm_arg_array_ptr),
            ],
            unsafe { WasmRuntime.as_mut().unwrap() },
        )
        .expect("Failed test StpCallbackEntry");
    println!("{:#x} {:#x}", fake_arg, fake_arg_ptr);

    strace_core::dealloc_wasm(
        unsafe { WasmModule.clone().unwrap() },
        unsafe { WasmRuntime.as_mut().unwrap() },
        wasm_arg_array_ptr,
        8 * 8,
    );
    println!("Done with main!");

    loop {
        mockStpCallbackEntry(1337);
    }
}
