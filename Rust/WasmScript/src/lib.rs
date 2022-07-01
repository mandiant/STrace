pub mod machinestate;
use machinestate::MachineState;

extern "C" {
    pub fn access_memory(
        SafeAddress: u64,
        UnsafeAddress: u64,
        NumberOfBytes: u64,
        ChunkSize: u64,
        DoRead: bool,
    ) -> bool;
    pub fn log_impl(msg: *const u8, msg_len: u32);
    pub fn set_callback_impl(
        syscallName: *const char,
        syscallNameLen: u32,
        isEntry: bool,
        probeId: u64,
    ) -> bool;
}

fn set_callback(syscallName: &str, isEntry: bool, probeId: u64) -> bool {
    unsafe {
        return set_callback_impl(
            syscallName.as_ptr() as *const char,
            syscallName.len() as u32,
            isEntry,
            probeId,
        );
    }
}

fn log(msg: &str) {
    unsafe { log_impl(msg.as_ptr(), msg.len() as u32) }
}

fn strace_mem_read<const N: usize>(from: u64, to: &mut [u8; N]) {
    unsafe {
        access_memory(to.as_mut_ptr() as u64, from, N as u64, 8, true);
    }
}

fn strace_mem_write<const N: usize>(from: &[u8; N], to: u64) {
    unsafe {
        access_memory(from.as_ptr() as u64, to, N as u64, 8, false);
    }
}

#[no_mangle]
pub extern "system" fn StpCallbackEntry(
    pService: u64,
    probeId: u32,
    paramCount: u32,
    pRegs: *const u64,
    regArgSize: u32,
    pStackArgs: *const u64,
) -> () {
    // let ctx = MachineState::new(paramCount, regArgSize, pStackArgs, pRegs);
    let msg = format!("Entry called with {} {}", pService, probeId);
    log(msg.as_str());
}

#[no_mangle]
pub extern "system" fn StpCallbackReturn(
    _pService: u64,
    _probeId: u32,
    paramCount: u32,
    pRegs: *const u64,
    regArgSize: u32,
    pStackArgs: *const u64,
) -> () {
    //let _ctx = MachineState::new(paramCount, regArgSize, pStackArgs, pRegs);
}

#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut std::os::raw::c_void {
    let ptr = unsafe {
        std::alloc::alloc(
            std::alloc::Layout::from_size_align(size, 1).expect("allocation layout failed"),
        )
    };
    return ptr as *mut std::os::raw::c_void;
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut std::os::raw::c_void, size: usize) {
    unsafe {
        std::alloc::dealloc(
            ptr as *mut u8,
            std::alloc::Layout::from_size_align(size, 1).expect("deallocation layout failed"),
        );
    }
}

#[no_mangle]
pub extern "C" fn strace_initialize() {
    log("Hello STRACE!");
    set_callback("QuerySystemInformation", true, 0);
    log("Callback Set!");
}
