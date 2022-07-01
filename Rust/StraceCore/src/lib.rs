#![no_std]
use alloc::string::ToString;
use lazy_static::lazy_static;
pub use wasmi::{
    memory_units::Bytes, Externals, FuncInstance, FuncRef, ImportsBuilder, MemoryRef, Module,
    ModuleImportResolver, ModuleInstance, ModuleRef, RuntimeArgs, RuntimeValue, Signature, Trap,
    ValueType,
};

#[macro_use]
extern crate alloc;

#[no_mangle]
#[inline(never)]
pub extern "system" fn TraceAccessMemory(
    SafeAddress: u64,
    UnsafeAddress: u64,
    NumberOfBytes: u64,
    ChunkSize: u64,
    DoRead: bool,
) -> bool {
    let mut source = UnsafeAddress; //dowrite SafeAddress
    let mut dest = SafeAddress; // dowrite UnsafeAddress

    if !DoRead {
        let tmp = source;
        source = dest;
        dest = tmp;
    }

    let mut bytesLeft = NumberOfBytes;
    while bytesLeft > 0 {
        // chunksize should be multiple of byte count or you get over/under issues
        if bytesLeft < ChunkSize {
            return false;
        }

        match ChunkSize {
            1 => unsafe {
                *(dest as *mut u8) = *(source as *const u8);
            },
            2 => unsafe {
                *(dest as *mut u16) = *(source as *const u16);
            },
            4 => unsafe {
                *(dest as *mut u32) = *(source as *const u32);
            },
            8 => unsafe {
                *(dest as *mut u64) = *(source as *const u64);
            },
            _ => {
                // error
                return false;
            }
        }

        bytesLeft -= ChunkSize;
        source += ChunkSize;
        dest += ChunkSize;
    }
    true
}

pub fn check_export_exists(module: &ModuleRef, export_name: &str) -> bool {
    match module.export_by_name(export_name) {
        Some(_export) => true,
        None => false,
    }
}

const FUNCIDX_ACCESS_MEMORY: usize = 0;
const FUNCIDX_LOG: usize = 1;
const FUNCIDX_SETCALLBACK: usize = 2;

lazy_static! {
    static ref FUNC_ACCESS_MEMORY_SIG: Signature = Signature::new(
        &[
            ValueType::I64,
            ValueType::I64,
            ValueType::I64,
            ValueType::I64,
            ValueType::I32
        ][..],
        Some(ValueType::I32)
    );
    static ref FUNC_LOG_SIG: Signature =
        Signature::new(&[ValueType::I32, ValueType::I32][..], None);
    static ref FUNC_SETCALLBACK_SIG: Signature = Signature::new(
        &[
            ValueType::I32,
            ValueType::I32,
            ValueType::I32,
            ValueType::I64
        ][..],
        Some(ValueType::I32)
    );
}

pub type LOG_ROUTINE = fn(msg: &str);
pub type SETCALLBACK_ROUTINE = fn(syscallName: &str, isEntry: bool, probeId: u64) -> bool;

pub struct Runtime {
    pub module: ModuleRef,
    pub memory: MemoryRef,
    pub log_routine: LOG_ROUTINE,
    pub set_callback: SETCALLBACK_ROUTINE,
}

impl Externals for Runtime {
    fn invoke_index(
        &mut self,
        index: usize,
        args: RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, Trap> {
        let direct_mem = self.memory.direct_access();
        let wasm_direct_mem = direct_mem.as_ref();

        match index {
            FUNCIDX_ACCESS_MEMORY => {
                let safeaddr: u64 = args.nth_checked(0)?;
                let addr: u64 = args.nth_checked(1)?;
                let numberofbytes: u64 = args.nth_checked(2)?;
                let chunksize: u64 = args.nth_checked(3)?;
                let doread: bool = args.nth_checked(4)?;

                let status;
                let memsize: Bytes = self.memory.current_size().into();

                if Bytes(safeaddr as usize + numberofbytes as usize) > memsize {
                    status = false;
                } else {
                    status = TraceAccessMemory(
                        ((&wasm_direct_mem[safeaddr as usize]) as *const u8) as u64,
                        addr,
                        numberofbytes,
                        chunksize,
                        doread,
                    );
                }

                Ok(Some(RuntimeValue::I32(status as i32)))
            }
            FUNCIDX_LOG => {
                let addr: u32 = args.nth_checked(0)?;
                let length: u32 = args.nth_checked(1)?;

                let string = read_wasm_string(addr, length, &wasm_direct_mem);
                (self.log_routine)(string);
                Ok(None)
            }
            FUNCIDX_SETCALLBACK => {
                let syscallNameAddr: u32 = args.nth_checked(0)?;
                let syscallNameLen: u32 = args.nth_checked(1)?;
                let syscallName =
                    read_wasm_string(syscallNameAddr, syscallNameLen, &wasm_direct_mem);

                let isEntry: u32 = args.nth_checked(2)?;
                let probeId: u64 = args.nth_checked(3)?;
                let status = (self.set_callback)(syscallName, isEntry != 0, probeId);
                Ok(Some(RuntimeValue::I32(status as i32)))
            }
            _ => panic!("Unimplemented function at {}", index),
        }
    }
}

pub struct HostExternals;
impl HostExternals {
    fn check_signature(&self, index: usize, signature: &Signature) -> bool {
        // webassembly is type safe, this verifies that the wasm type signature from the module matches what we expect
        let sig = match index {
            FUNCIDX_ACCESS_MEMORY => (*FUNC_ACCESS_MEMORY_SIG).clone(),
            FUNCIDX_LOG => (*FUNC_LOG_SIG).clone(),
            FUNCIDX_SETCALLBACK => (*FUNC_SETCALLBACK_SIG).clone(),
            _ => return false,
        };

        signature.params() == sig.params() && signature.return_type() == sig.return_type()
    }
}

impl ModuleImportResolver for HostExternals {
    fn resolve_func(
        &self,
        field_name: &str,
        signature: &Signature,
    ) -> Result<FuncRef, wasmi::Error> {
        let (index, sig) = match field_name {
            "access_memory" => (FUNCIDX_ACCESS_MEMORY, (*FUNC_ACCESS_MEMORY_SIG).clone()),
            "log_impl" => (FUNCIDX_LOG, (*FUNC_LOG_SIG).clone()),
            "set_callback_impl" => (FUNCIDX_SETCALLBACK, (*FUNC_SETCALLBACK_SIG).clone()),
            _ => {
                return Err(wasmi::Error::Instantiation(format!(
                    "Export {} not found",
                    field_name
                )))
            }
        };

        if !self.check_signature(index, signature) {
            return Err(wasmi::Error::Instantiation(format!(
                "Export {} has a bad signature, got {:?}",
                field_name, signature
            )));
        }

        Ok(FuncInstance::alloc_host(sig, index))
    }
}

pub fn read_wasm_string(offset: u32, length: u32, wasm_mem: &[u8]) -> &str {
    core::str::from_utf8(&wasm_mem[offset as usize..offset as usize + length as usize])
        .expect("read_wasm_cstring failed to parse invalid utf-8 string")
}

pub fn alloc_wasm(module: ModuleRef, runtime: &mut Runtime, size: u32) -> i32 {
    if let RuntimeValue::I32(wasm_ptr) = module
        .invoke_export("alloc", &[RuntimeValue::I32(size as i32)], runtime)
        .expect("Failed to invoke alloc")
        .expect("failed allocation")
    {
        return wasm_ptr;
    }
    return 0;
}

pub fn dealloc_wasm(module: ModuleRef, runtime: &mut Runtime, wasm_ptr: i32, size: u32) {
    module
        .invoke_export(
            "dealloc",
            &[RuntimeValue::I32(wasm_ptr), RuntimeValue::I32(size as i32)],
            runtime,
        )
        .expect("Failed to invoke alloc");
}

pub fn loadStraceWasmModule(
    buf: &[u8],
    exports: &[&str],
    log_routine: LOG_ROUTINE,
    set_callback: SETCALLBACK_ROUTINE,
) -> Result<(wasmi::ModuleRef, Runtime), wasmi::Error> {
    let modbuf = wasmi::Module::from_buffer(buf)?;
    let mut imports = ImportsBuilder::new();
    imports.push_resolver("env", &HostExternals);

    let main = ModuleInstance::new(&modbuf, &imports)?.assert_no_start();

    // "memory" is the export name of the region wasm uses for all its memory. It is usually called that, but YMMV.
    let memory_export = main
        .export_by_name("memory")
        .ok_or(wasmi::Error::Validation(
            "memory export missing".to_string(),
        ))?;
    let memory = memory_export.as_memory().ok_or(wasmi::Error::Validation(
        "memory export not a memory type".to_string(),
    ))?;

    let runtime = Runtime {
        module: main.clone(),
        memory: memory.clone(),
        log_routine,
        set_callback,
    };

    for export in exports.iter() {
        if !check_export_exists(&main, export) {
            return Err(wasmi::Error::Validation("Export missing".to_string()));
        }
    }

    Ok((main, runtime))
}
