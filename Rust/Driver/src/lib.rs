#![no_std]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![feature(alloc_error_handler)]
#![feature(new_uninit)]
#![feature(core_intrinsics)]
#![feature(link_llvm_intrinsics)]
// sad: not implemented yet
//#![feature(unnamed_fields)]

pub mod float;
pub mod log;
pub mod machinestate;
pub mod ntcompat;
pub mod strace;

// import order matters
// set "rust-analyzer.checkOnSave.allTargets": false in rust-analyzer
// preferences to suppress weird warning
use core::{intrinsics::transmute, mem::MaybeUninit, panic::PanicInfo};
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        log(format!("Panic occurred: {:?}", info).as_str());
        nt::ntdbg::DbgBreakPoint();
    }
    loop {}
}

#[no_mangle]
extern "C" fn __chkstk() {}
#[no_mangle]
extern "C" fn __CxxFrameHandler3() {}

#[macro_use] extern crate alloc;
#[macro_use] extern crate bitflags;
extern crate spin;

use log::{log, Log};
use ntapi::ntioapi::FILE_DEVICE_SECURE_OPEN;
use ntcompat::{
    basedef::*,
    device_object::*,
    driver_object::*,
    irp::{CTL_CODE, IRP, IRP_MJ},
    nt::{self},
    status::Status,
    string::UnicodeString,
};
use strace_core::{self, ModuleRef, Runtime, RuntimeValue};

use crate::{
    machinestate::MachineState,
    ntcompat::{nt::KeExpandKernelStackAndCalloutEx, string::a2u},
};

const DRIVER_POOL_TAG: ULONG = 0x537478; // 'Stx'
const DRIVER_NAME_WITH_EXT: &str = "strace.sys";
const NT_DEVICE_NAME: &str = "\\Device\\STrace";
const DOS_DEVICES_LINK_NAME: &str = "\\DosDevices\\STrace";
const IOCTL_STRACE_BEGIN: u64 = CTL_CODE(
    FILE_DEVICE_UNKNOWN as u64,
    0x800 + 0,
    METHOD_BUFFERED as u64,
    FILE_SPECIAL_ACCESS as u64,
);

struct Globals {
    WasmModule: ModuleRef,
    WasmRuntime: Runtime,
    Log: Log,
}

type GlobalPointer = *mut Globals;
static mut pGlobals: spin::Mutex<GlobalPointer> =
    spin::Mutex::<GlobalPointer>::new(0 as GlobalPointer);

fn read_globals(mut mutex_guard: spin::MutexGuard<GlobalPointer>) -> Option<&mut Globals> {
    if *mutex_guard as u64 != 0 {
        // lock mutex, then deref once to get mutex data, which is a pointer, deref
        // again, but then &mut to refer to our global struct as mutable struct by value
        return Some(unsafe { &mut (*(*mutex_guard)) });
    }
    return None;
}

pub fn callout_wasm() {
    // wasmi eats stack, call it with a new stack at the maximum size the nt kernel
    // allows
    unsafe {
        KeExpandKernelStackAndCalloutEx(
            initialize_wasm,
            0 as PVOID,
            MAXIMUM_EXPANSION_SIZE as u64,
            0,
            0 as PVOID,
        );
    }
}

/**
The StpCallbackEntry and StpCallbackReturn routines must either be re-entrant, or hold a lock for operations that involve global state. It is ok
to hold a spin lock here, this are invoked at IRQL: LOW_LEVEL.
**/

#[no_mangle]
pub extern "system" fn StpCallbackEntry(
    _pService: u64, probeId: u32, paramCount: u32, pRegs: *const u64, regArgSize: u32,
    pStackArgs: *const u64,
) -> () {
    let _ctx = MachineState::new(paramCount, regArgSize, pStackArgs, pRegs);

    let mut global_lock = unsafe { pGlobals.lock() };
    let global_ref = read_globals(global_lock).expect("Failed to deref globals");
    let main = global_ref.WasmModule.clone();
    let runtime = &mut global_ref.WasmRuntime;

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

#[no_mangle]
pub extern "system" fn StpCallbackReturn(
    _pService: u64, probeId: u32, paramCount: u32, pRegs: *const u64, regArgSize: u32,
    pStackArgs: *const u64,
) -> () {
    let ctx = MachineState::new(paramCount, regArgSize, pStackArgs, pRegs);
    let _retVal = ctx.read_arg(0);

    let global_lock = unsafe { pGlobals.lock() };
    let global_ref = read_globals(global_lock).expect("Failed to deref globals");
}

pub fn set_callback(syscallName: &str, isEntry: bool, probeId: u64) -> bool {
    // TODO: set callback pointer
    let nullSyscallName = format!("{}\x00", syscallName);
    let callback: u64 = unsafe {
        core::intrinsics::transmute(if isEntry {
            StpCallbackEntry as PVOID
        } else {
            StpCallbackReturn as PVOID
        })
    };

    return unsafe {
        ((*strace::TRACE_SYSTEM_API).KeSetSystemServiceCallback)(
            nullSyscallName.as_ptr() as *const char,
            isEntry,
            callback,
            probeId,
        )
        .is_ok()
    };
}

extern "system" fn initialize_wasm(Parameter: PVOID) {
    if cfg!(debug_assertions) {
        unsafe { nt::ntdbg::DbgBreakPoint() };
    }

    match strace_core::loadStraceWasmModule(
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
    ) {
        Ok((main, mut runtime)) => {
            // run wasm script's initializer
            main.invoke_export("strace_initialize", &[], &mut runtime)
                .expect("Failed STrace wasm initialization");

            let mut globals = unsafe { pGlobals.lock() };
            let new_ptr = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(Globals {
                WasmModule: main,
                WasmRuntime: runtime,
                Log: Log::new(log::LOG_OPTIONS::DEFAULT, "\\??\\C:\\strace.log"),
            }));
            *globals = new_ptr;
        }
        Err(err) => {
            log(format!("Failed to load wasm module: {}", err).as_str());
            return;
        }
    }
}

#[no_mangle]
pub extern "system" fn DriverEntry(driver: &mut DRIVER_OBJECT, _path: &UnicodeString) -> Status {
    // Break into a debugger with a debug build.
    if cfg!(debug_assertions) {
        unsafe { nt::ntdbg::DbgBreakPoint() };
    }

    log("STrace driver entry...");

    let NtDeviceName = a2u(NT_DEVICE_NAME);
    let mut device: *mut DEVICE_OBJECT = core::ptr::null_mut();
    let mut status = unsafe {
        IoCreateDevice(
            driver,
            0,
            &NtDeviceName,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            false,
            &mut device,
        )
    };
    if status.is_err() {
        return status;
    }

    let device = unsafe { &mut *device };
    driver.MajorFunction[IRP_MJ::CREATE as usize] = Some(DeviceCreate);
    driver.MajorFunction[IRP_MJ::CLOSE as usize] = Some(DeviceClose);
    driver.MajorFunction[IRP_MJ::CLEANUP as usize] = Some(DeviceCleanup);
    driver.MajorFunction[IRP_MJ::DEVICE_CONTROL as usize] = Some(DeviceControl);
    driver.DriverUnload = Some(DeviceUnload);
    driver.DeviceObject = device;

    let DosDevicesLinkName = a2u(DOS_DEVICES_LINK_NAME);
    status = unsafe { IoCreateSymbolicLink(&DosDevicesLinkName, &NtDeviceName) };
    if status.is_err() {
        unsafe { IoDeleteDevice(device) };
        return status;
    }
    Status::SUCCESS
}

extern "system" fn DeviceUnload(driver: &mut DRIVER_OBJECT) { log("STrace Unload"); }

extern "system" fn DeviceCreate(_device: &mut DEVICE_OBJECT, irp: &mut IRP) -> Status {
    return irp.complete_request(Status::SUCCESS);
}

extern "system" fn DeviceClose(_device: &mut DEVICE_OBJECT, irp: &mut IRP) -> Status {
    return irp.complete_request(Status::SUCCESS);
}

extern "system" fn DeviceCleanup(device: &mut DEVICE_OBJECT, irp: &mut IRP) -> Status {
    return irp.complete_request(Status::SUCCESS);
}

extern "system" fn DeviceControl(device: &mut DEVICE_OBJECT, irp: &mut IRP) -> Status {
    let io = irp.get_current_stack_location();
    let control_args = io.ParametersDeviceIoControl();
    match control_args.IoControlCode {
        IOCTL_STRACE_BEGIN => {
            callout_wasm();
        }
        _ => {}
    }
    return irp.complete_request(Status::SUCCESS);
}
