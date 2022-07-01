use core::{intrinsics::size_of, mem};

use alloc::{boxed::Box, string::String};
use ntapi::{
    ntioapi::{FILE_NON_DIRECTORY_FILE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT},
    ntzwapi::ZwOpenFile,
};
use winapi::{
    shared::{
        ntdef::{
            NULL, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, OBJ_KERNEL_HANDLE, PLARGE_INTEGER,
            PULONG, UNICODE_STRING,
        },
        ntstatus::STATUS_SUCCESS,
    },
    um::winnt::{
        FILE_APPEND_DATA, FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_READ, FILE_WRITE_DATA, PHANDLE,
        SYNCHRONIZE,
    },
};

use crate::ntcompat::{
    basedef::IO_STATUS_BLOCK,
    nt::{self, ZwCreateFile, ZwDeleteFile, ZwWriteFile, HANDLE, PVOID},
    status::Status,
    string::{a2u, UnicodeString},
};
pub use ntapi::ntdbg::DbgPrintEx;
pub const DPFLTR_IHVDRIVER_ID: u32 = 77;
pub const DPFLTR_ERROR_LEVEL: u32 = 0;

pub fn log(msg: &str) {
    unsafe {
        crate::log::DbgPrintEx(
            crate::log::DPFLTR_IHVDRIVER_ID,
            crate::log::DPFLTR_ERROR_LEVEL,
            format!("{}\n\0", msg).as_ptr() as *const i8,
        );
    }
}

bitflags! {
    pub struct LOG_OPTIONS: u64 {
        const DEFAULT =               0b00000000;
        const LOG_PUT_LEVEL_DISABLE =            0b00000001;
        const LOG_LEVEL_OPT_SAFE =               0b00000010;
        const LOG_LEVEL_DEBUG =                  0b00000100;
        const LOG_LEVEL_INFO =                   0b00001000;
        const LOG_LEVEL_WARN =                   0b00010000;
        const LOG_LEVEL_ERROR =                  0b00100000;

        // const LOG_OPT_DISABLE_TIME =              0b00100000;
        // const LOG_OPT_DISABLE_FUNCTION_NAME =      0b01000000;
        // const LOG_OPT_DISABLE_PROCESSOR_NUMBER =   0b10000000;

        const LOG_OPT_DISABLE_APPEND =           0b100000000;

        const LOG_PUT_LEVEL_DEBUG = Self::LOG_LEVEL_ERROR.bits | Self::LOG_LEVEL_WARN.bits | Self::LOG_LEVEL_INFO.bits | Self::LOG_LEVEL_DEBUG.bits;
        const LOG_PUT_LEVEL_INFO = Self::LOG_LEVEL_ERROR.bits | Self::LOG_LEVEL_WARN.bits | Self::LOG_LEVEL_INFO.bits;
        const LOG_PUT_LEVEL_WARN = Self::LOG_LEVEL_ERROR.bits | Self::LOG_LEVEL_WARN.bits;
        const LOG_PUT_LEVEL_ERROR = Self::LOG_LEVEL_ERROR.bits;
    }
}

pub struct Log {
    Flags: LOG_OPTIONS,
    LogFileHandle: HANDLE,
}

impl Log {
    pub fn new(Flag: LOG_OPTIONS, LogFilePath: &str) -> Self {
        let mut path = a2u(LogFilePath);
        let attributes = OBJECT_ATTRIBUTES {
            Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: NULL,
            ObjectName: &mut path as *mut UNICODE_STRING,
            Attributes: OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: NULL,
            SecurityQualityOfService: NULL,
        };

        if Flag.contains(LOG_OPTIONS::LOG_OPT_DISABLE_APPEND) {
            let status = unsafe { ZwDeleteFile(&attributes as *const OBJECT_ATTRIBUTES) };
            if status.is_err() {
                panic!("Log initialize deletion failed");
            }
        }

        let desired_access = match Flag.contains(LOG_OPTIONS::LOG_OPT_DISABLE_APPEND) {
            true => FILE_WRITE_DATA | SYNCHRONIZE,
            false => FILE_APPEND_DATA | SYNCHRONIZE,
        };

        let mut hFile: HANDLE = Default::default();
        let mut ioStatus: IO_STATUS_BLOCK = Default::default();
        let status = unsafe {
            ZwCreateFile(
                &mut hFile as *mut HANDLE as PHANDLE,
                desired_access,
                &attributes as *const OBJECT_ATTRIBUTES,
                &mut ioStatus as *mut IO_STATUS_BLOCK,
                NULL as PLARGE_INTEGER,
                FILE_ATTRIBUTE_SYSTEM,
                FILE_SHARE_READ,
                FILE_OPEN_IF,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                0,
                0,
            )
        };
        if status.is_err() {
            panic!("Failed to create log file");
        }

        Log {
            Flags: Flag,
            LogFileHandle: hFile,
        }
    }

    fn getPrefix(&self, Flag: LOG_OPTIONS) -> &str {
        return match self.Flags {
            LOG_OPTIONS::LOG_PUT_LEVEL_DEBUG => "[DEBUG]",
            LOG_OPTIONS::LOG_PUT_LEVEL_ERROR => "[ERROR]",
            LOG_OPTIONS::LOG_PUT_LEVEL_INFO => "[INFO]",
            LOG_OPTIONS::LOG_PUT_LEVEL_WARN => "[WARN]",
            LOG_OPTIONS::LOG_PUT_LEVEL_DISABLE => "",
            _ => "",
        };
    }

    fn log_impl(&self, message: &str, Flag: LOG_OPTIONS) -> Status {
        let prefix = self.getPrefix(Flag);
        let mut ioStatus: IO_STATUS_BLOCK = Default::default();

        let logBuf = format!("{}{}\x00", prefix, message);
        let status = unsafe {
            ZwWriteFile(
                self.LogFileHandle,
                0,
                NULL,
                NULL,
                &mut ioStatus as *mut IO_STATUS_BLOCK,
                logBuf.as_ptr() as PVOID,
                logBuf.len() as u32,
                NULL as PLARGE_INTEGER,
                NULL as PULONG,
            )
        };

        status
    }

    pub fn log_debug(&self, message: &str) -> Status {
        return self.log_impl(message, LOG_OPTIONS::LOG_PUT_LEVEL_DEBUG);
    }

    pub fn log_info(&self, message: &str) -> Status {
        return self.log_impl(message, LOG_OPTIONS::LOG_PUT_LEVEL_INFO);
    }

    pub fn log_warn(&self, message: &str) -> Status {
        return self.log_impl(message, LOG_OPTIONS::LOG_PUT_LEVEL_WARN);
    }

    pub fn log_error(&self, message: &str) -> Status {
        return self.log_impl(message, LOG_OPTIONS::LOG_PUT_LEVEL_ERROR);
    }
}
