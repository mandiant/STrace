//! Kernel mode string types.

use super::{basedef::NTSTATUS, status::Status};
use winapi::shared::ntdef::UNICODE_STRING;

/// NT native string types.
pub trait NativeString {
    /// Size of string in bytes.
    fn size(&self) -> u16;
    /// Size of buffer in bytes.
    fn max_size(&self) -> u16;

    /// Check is the string is empty.
    fn is_empty(&self) -> bool { self.size() == 0u16 }
}

/// A counted string used for ANSI strings.
#[repr(C)]
pub struct ANSI_STRING {
    /// The length in *bytes* of the string stored in `Buffer`.
    pub Length: u16,
    /// The length in bytes of `Buffer`.
    pub MaximumLength: u16,
    /// Pointer to a buffer used to contain a string of characters.
    pub Buffer: *const u8,
}

impl NativeString for UNICODE_STRING {
    fn size(&self) -> u16 { self.Length }

    fn max_size(&self) -> u16 { self.MaximumLength }
}

impl<'a> From<&'a str> for ANSI_STRING {
    fn from(s: &'a str) -> Self {
        let b = s.as_bytes();
        let len = b.len();
        assert!(
            len > 0 && b[len - 1] == 0,
            "AnsiString bytes must be null terminated"
        );
        ANSI_STRING {
            Length: (len - 1) as u16,
            MaximumLength: len as u16,
            Buffer: b.as_ptr(),
        }
    }
}

pub type AnsiString = ANSI_STRING;
pub type UnicodeString = UNICODE_STRING;
pub type CONST_UNICODE_STRING = UNICODE_STRING;
pub type CONST_ANSI_STRING = ANSI_STRING;

pub type PUNICODE_STRING = *mut UNICODE_STRING;
pub type PCUNICODE_STRING = *const UNICODE_STRING;

extern "system" {
    pub fn RtlIntegerToUnicodeString(Value: u32, Base: u32, String: &mut UNICODE_STRING) -> Status;
    pub fn RtlInt64ToUnicodeString(Value: u64, Base: u32, String: &mut UNICODE_STRING) -> Status;
    pub fn RtlUnicodeStringToInteger(
        String: &CONST_UNICODE_STRING, Base: u32, Value: &mut u32,
    ) -> Status;

    pub fn RtlUnicodeStringToAnsiString(
        DestinationString: &mut ANSI_STRING, SourceString: &CONST_UNICODE_STRING,
        AllocateDestination: bool,
    ) -> Status;
    pub fn RtlUnicodeStringToAnsiSize(SourceString: &CONST_UNICODE_STRING) -> u32;

    pub fn RtlAnsiStringToUnicodeString(
        DestinationString: &mut UNICODE_STRING, SourceString: &CONST_ANSI_STRING,
        AllocateDestination: bool,
    ) -> Status;
    pub fn RtlAnsiStringToUnicodeSize(SourceString: &CONST_ANSI_STRING) -> u32;

    pub fn RtlCompareUnicodeString(
        String1: &CONST_UNICODE_STRING, String2: &CONST_UNICODE_STRING, CaseInSensitive: bool,
    ) -> i32;
    pub fn RtlCompareString(
        String1: &CONST_ANSI_STRING, String2: &CONST_ANSI_STRING, CaseInSensitive: bool,
    ) -> i32;

    pub fn RtlEqualUnicodeString(
        String1: &CONST_UNICODE_STRING, String2: &CONST_UNICODE_STRING,
    ) -> bool;
    pub fn RtlEqualString(String1: &CONST_ANSI_STRING, String2: &CONST_ANSI_STRING) -> bool;

    pub fn RtlFreeAnsiString(UnicodeString: &mut ANSI_STRING);
    pub fn RtlFreeUnicodeString(UnicodeString: &mut UNICODE_STRING);
}

pub fn a2u(s: &str) -> UnicodeString {
    let a = AnsiString::from(format!("{}\x00", s).as_str());
    let mut u = UnicodeString::default();
    unsafe { RtlAnsiStringToUnicodeString(&mut u, &a, true) };
    return u;
}
