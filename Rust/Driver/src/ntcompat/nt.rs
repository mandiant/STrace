pub use super::basedef::{ERESOURCE_THREAD, HANDLE, KSPIN_LOCK, NTSTATUS, PVOID};
use super::{
    basedef::{IO_STATUS_BLOCK, PIO_STATUS_BLOCK, ULONG},
    irp::IRP,
    status::Status,
};
pub use ntapi::{ntdbg, winapi::shared::ntdef};
pub use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use winapi::{
    shared::{
        minwindef::PULONG,
        ntdef::{LARGE_INTEGER, OBJECT_ATTRIBUTES, PLARGE_INTEGER, PLIST_ENTRY},
    },
    um::winnt::{ACCESS_MASK, BOOLEAN, PHANDLE},
};

#[repr(C)]
pub struct OWNER_ENTRY {
    OwnerThread: ERESOURCE_THREAD,
    TableSize: ntdef::ULONG,
}

#[repr(C)]
pub struct ERESOURCE {
    SystemResourcesList: ntdef::LIST_ENTRY,
    OwnerTable: *mut OWNER_ENTRY,

    ActiveCount: ntdef::SHORT,
    // _: union {
    //     Flag: ntdef::USHORT,
    //     _: struct {
    //         ReservedLowFlags: ntdef::UCHAR,
    //         WaiterPriority: ntdef::UCHAR
    //     }
    // }
    Flag: ntdef::USHORT,
    SharedWaiters: ntdef::PVOID,
    ExclusiveWaiters: ntdef::PVOID,
    OwnerEntry: OWNER_ENTRY,
    ActiveEntries: ntdef::ULONG,
    ContentionCount: ntdef::ULONG,
    NumberOfSharedWaiters: ntdef::ULONG,
    NumberOfExclusiveWaiters: ntdef::ULONG,

    Reserved2: ntdef::PVOID,

    // _: union {
    //     Address: ntdef::PVOID;
    //     CreatorBackTraceIndex: ntdef::ULONGLONG;
    // };
    Address: ntdef::PVOID,
    SpinLock: KSPIN_LOCK,
}

extern "system" {
    pub fn MmCopyMemory(
        TargetAddress: PVOID, SourceAddress: u64, NumberOfBytes: usize, Flags: u32,
        NumberOfBytesTransferred: *mut usize,
    ) -> Status;
    pub fn MmGetPhysicalAddress(BaseAddress: PVOID) -> u64;
    pub fn ExAllocatePool(PoolType: u32, NumberOfBytes: u64) -> *mut core::ffi::c_void;
    pub fn ExFreePool(pool: u64);
    pub fn KeExpandKernelStackAndCalloutEx(
        Callout: extern "system" fn(Parameter: PVOID), Parameter: PVOID, Size: u64, Wait: BOOLEAN,
        Context: PVOID,
    ) -> Status;
    pub fn ZwCreateFile(
        FileHandle: PHANDLE, DesiredAccess: ACCESS_MASK,
        ObjectAttributes: *const OBJECT_ATTRIBUTES, IoStatusBlock: PIO_STATUS_BLOCK,
        AllocationSize: PLARGE_INTEGER, FileAttributes: ULONG, ShareAccess: ULONG,
        CreateDisposition: ULONG, CreateOptions: ULONG, EaBuffer: ULONG, EaLength: ULONG,
    ) -> Status;
    pub fn ZwDeleteFile(ObjectAttributes: *const OBJECT_ATTRIBUTES) -> Status;
    pub fn ZwClose(Handle: HANDLE) -> Status;
    pub fn ZwWriteFile(
        FileHandle: HANDLE, Event: HANDLE, ApcRoutine: PVOID, ApcContext: PVOID,
        IoStatusBlock: PIO_STATUS_BLOCK, Buffer: PVOID, Length: ULONG, ByteOffset: PLARGE_INTEGER,
        Key: PULONG,
    ) -> Status;
}

extern "cdecl" {
    pub fn _snwprintf(Dest: ntdef::PWSTR, Count: usize, Format: ntdef::PCWSTR, ...) -> i32;
}
