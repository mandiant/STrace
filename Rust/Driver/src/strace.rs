use crate::{
    ntcompat::{
        basedef::KIRQL,
        irp::PIRP,
        nt::{self, PVOID},
        status::Status,
    },
    StpCallbackEntry, StpCallbackReturn,
};
use alloc::vec::Vec;
use strace_core::TraceAccessMemory;
use winapi::shared::ntdef::PKIRQL;

#[repr(C)]
pub struct TraceApi {
    pub supported_flags: u32,
    pub kthread_tracingprivatedata_offset: u32,
    pub kthread_tracingprivatedata_arraysize: u32,
    pub kthread_trapframe_offset: u32,
    pub kthread_teb_offset: u64,

    /**
    This handles probe registration and removal.
    syscallName: The system call name to register, with the first two characters skipped, ie without Nt or Zw prefix
    isEntry: Register an entry or return probe, must match callback entry or return pointer
    callback: The callback to invoke on entry/return must be StpCallbackEntry and StpCallbackReturn respectively matching isEntry
    probeId: A user given ID to remember the entry by, passed to the callback routine

    To remove a callback provide syscallName, isEntry to specify removal of entry/return probe then zero for callback and probeId
    **/
    pub KeSetSystemServiceCallback: extern "system" fn(
        syscallName: *const char,
        isEntry: bool,
        callback: u64,
        probeId: u64,
    ) -> Status,
    pub KeSetTracepoint: u64,
    pub EtwRegisterEventCallback: u64,
    pub PsGetBaseTrapFrame: u64,
    pub KiGetTrapFrameRegister: u64,
    pub MmEnumerateSystemImages: u64,
}

#[repr(C)]
pub struct TraceCallbacks {
    pub callbacks: *mut u64,
}

pub fn NotImplementedRoutine() -> Status { return Status::NOT_IMPLEMENTED; }

// null initialize, filled by TraceInitSystem later
pub static mut TRACE_SYSTEM_API: *mut TraceApi = 0 as *mut TraceApi;

#[no_mangle]
pub extern "system" fn TraceInitSystem(
    ppTraceApi: *mut *mut *mut TraceApi, pTraceTable: *mut TraceCallbacks,
    pMemTraceRoutine: *mut extern "system" fn(
        SafeAddress: u64,
        UnsafeAddress: u64,
        NumberOfBytes: u64,
        ChunkSize: u64,
        DoRead: bool,
    ) -> bool,
) -> Status {
    if cfg!(debug_assertions) {
        unsafe { nt::ntdbg::DbgBreakPoint() };
    }

    let max_idx: u64;
    let slice;
    unsafe {
        // trust me, it's all safe, i'm a scientist

        // ntoskern fills this table of pointers for us after load
        // these are the core APIs to interact with the dtrace kernel system
        *ppTraceApi = &mut TRACE_SYSTEM_API;

        // array size is 0th
        max_idx = (*pTraceTable).callbacks.offset(0) as u64;
        if max_idx == 0 {
            return Status::CANCELLED;
        }

        // values start at 1st slot address
        slice =
            core::slice::from_raw_parts_mut(&mut ((*pTraceTable).callbacks), max_idx as usize - 1);

        // give kernel our custom memory access routine
        *pMemTraceRoutine = TraceAccessMemory;
    }

    // register our callback routines the kernel can fire when probes hit
    for (idx, slot) in slice.iter_mut().skip(1).enumerate() {
        // type erase the pointer
        let callback: *const core::ffi::c_void = match idx {
            // DtEtwpEventCallback
            0 => NotImplementedRoutine as _,
            1 => StpCallbackEntry as _,
            2 => StpCallbackReturn as _,
            // FbtpCallback
            3 => NotImplementedRoutine as _,
            // FbtpCallback
            4 => NotImplementedRoutine as _,
            // FtpPidCallback
            5 => NotImplementedRoutine as _,
            // FtpPidCallback
            6 => NotImplementedRoutine as _,
            // FbtpImageUnloadCallback
            7 => NotImplementedRoutine as _,
            _ => NotImplementedRoutine as _,
        };

        *slot = callback as _;
    }
    Status::SUCCESS
}
