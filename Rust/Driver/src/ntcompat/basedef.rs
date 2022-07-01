//! Kernel-Mode Types.

//|Type                        | S/U | x86    | x64
//|----------------------------+-----+--------+-------
//|BYTE, BOOLEAN               | U   | 8 bit  | 8 bit
//|----------------------------+-----+--------+-------
//|SHORT                       | S   | 16 bit | 16 bit
//|USHORT, WORD                | U   | 16 bit | 16 bit
//|----------------------------+-----+--------+-------
//|INT, LONG                   | S   | 32 bit | 32 bit
//|UINT, ULONG, DWORD          | U   | 32 bit | 32 bit
//|----------------------------+-----+--------+-------
//|INT_PTR, LONG_PTR, LPARAM   | S   | 32 bit | 64 bit
//|UINT_PTR, ULONG_PTR, WPARAM | U   | 32 bit | 64 bit
//|----------------------------+-----+--------+-------
//|LONGLONG                    | S   | 64 bit | 64 bit
//|ULONGLONG, QWORD            | U   | 64 bit | 64 bit

use winapi::shared::ntdef::LIST_ENTRY;

pub use super::irql::KIRQL;
pub type CHAR = i8;
pub type CCHAR = i8;
pub type USHORT = u16;
pub type CSHORT = i16;
pub type ULONG = u32;

pub type VOID = winapi::shared::ntdef::VOID;
pub type PVOID = winapi::shared::ntdef::PVOID;
pub type PCVOID = *const winapi::shared::ntdef::VOID;
pub type HANDLE = u64;

pub type NTSTATUS = i64;
pub type SIZE_T = usize;

pub type ULONG_PTR = usize;

pub type PEPROCESS = PVOID;
pub type PETHREAD = PVOID;
pub type PSECURITY_DESCRIPTOR = PVOID;

pub type PGUID = PVOID;
pub type PCGUID = PCVOID;

pub type PSTR = *mut u8;
pub type PWSTR = *mut u16;
pub type PCSTR = *const u8;
pub type PCWSTR = *const u16;

pub type PIO_APC_ROUTINE = Option<
    extern "system" fn(ApcContext: PCVOID, IoStatusBlock: *const IO_STATUS_BLOCK, Reserved: u32),
>;
pub type ERESOURCE_THREAD = PVOID;

pub const METHOD_BUFFERED: ULONG = 0;
pub const METHOD_IN_DIRECT: ULONG = 1;
pub const METHOD_OUT_DIRECT: ULONG = 2;
pub const METHOD_NEITHER: ULONG = 3;

pub const FILE_ANY_ACCESS: ULONG = 0;
pub const FILE_SPECIAL_ACCESS: ULONG = FILE_ANY_ACCESS;
pub const FILE_READ_ACCESS: ULONG = 0x0001; // file & pipe
pub const FILE_WRITE_ACCESS: ULONG = 0x0002; // file & pipe

pub const FILE_DEVICE_UNKNOWN: ULONG = 0x00000022;
pub const MAXIMUM_EXPANSION_SIZE: ULONG = 0x11800;

pub const PAGE_SIZE: u32 = 0x1000;
pub const NON_PAGED_POOL_NX: u32 = 512;

extern "system" {
    pub fn KeGetCurrentIrql() -> KIRQL;
    pub fn KeRaiseIrqlToDpcLevel() -> KIRQL;
}

/// Spin Lock.
#[repr(C)]
#[derive(Default)]
pub struct KSPIN_LOCK {
    pub lock: usize,
}

/// Common dispatcher object header.
#[repr(C)]
pub struct DISPATCHER_HEADER {
    pub Type: u8,
    pub Absolute: u8,
    pub Size: u8,
    pub Inserted: u8,
    pub SignalState: i32,
    pub WaitListHead: LIST_ENTRY,
}

/// An I/O status block.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct IO_STATUS_BLOCK {
    /// Completion status.
    pub Status: super::status::Status,
    /// Request-dependent value.
    pub Information: usize,
}

pub type PIO_STATUS_BLOCK = *mut IO_STATUS_BLOCK;

impl IO_STATUS_BLOCK {
    /// Return integer value for `Information` field.
    pub fn as_size(&self) -> usize { self.Information }

    /// Return the pointer of specified object type.
    pub fn as_ptr<T>(&self) -> *const T { unsafe { ::core::mem::transmute(self.Information) } }
}

/// Processor modes.
#[repr(u8)]
#[derive(Copy, Clone)]
pub enum KPROCESSOR_MODE {
    KernelMode,
    UserMode,
}

/// I/O Request priority.
pub mod IO_PRIORITY {
    /// I/O Request priority type.
    pub type KPRIORITY_BOOST = u8;

    pub const IO_NO_INCREMENT: KPRIORITY_BOOST = 0;
    pub const IO_DISK_INCREMENT: KPRIORITY_BOOST = 1;
    pub const EVENT_INCREMENT: KPRIORITY_BOOST = 1;
}

pub type KPRIORITY = IO_PRIORITY::KPRIORITY_BOOST;

/// Memory Descriptor List (MDL)
#[repr(C)]
pub struct MDL {
    Next: *mut MDL,
    Size: i16,
    MdlFlags: i16,
    Process: PEPROCESS,
    MappedSystemVa: PVOID,
    StartVa: PVOID,
    ByteCount: u32,
    ByteOffset: u32,
}

pub type PMDL = *mut MDL;

#[repr(i16)]
pub enum MDL_FLAGS {
    MDL_MAPPED_TO_SYSTEM_VA = 0x0001,
    MDL_PAGES_LOCKED = 0x0002,
    MDL_SOURCE_IS_NONPAGED_POOL = 0x0004,
    MDL_ALLOCATED_FIXED_SIZE = 0x0008,
    MDL_PARTIAL = 0x0010,
    MDL_PARTIAL_HAS_BEEN_MAPPED = 0x0020,
    MDL_IO_PAGE_READ = 0x0040,
    MDL_WRITE_OPERATION = 0x0080,
    MDL_PARENT_MAPPED_SYSTEM_VA = 0x0100,
    MDL_LOCK_HELD = 0x0200,
    MDL_SCATTER_GATHER_VA = 0x0400,
    MDL_IO_SPACE = 0x0800,
    MDL_NETWORK_HEADER = 0x1000,
    MDL_MAPPING_CAN_FAIL = 0x2000,
    MDL_ALLOCATED_MUST_SUCCEED = 0x4000,
}
