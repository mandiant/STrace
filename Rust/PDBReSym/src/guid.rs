#![allow(clippy::many_single_char_names)]

/// A globally unique identifier ([GUID](https://docs.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid))
/// used to identify COM and WinRT interfaces.
#[repr(C)]
// TODO: write these out
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl GUID {
    /// Creates a `GUID` represented by the all-zero byte-pattern.
    pub const fn zeroed() -> Self {
        Self {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    pub fn from_le_bytes(data: [u8; 16]) -> Self {
        let data1 = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let data2 = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let data3 = u16::from_le_bytes(data[6..8].try_into().unwrap());
        let data4: [u8; 8] = data[8..].try_into().unwrap();
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Creates a `GUID` with the given constant values.
    pub const fn from_values(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    pub fn as_hex_str(self: &Self) -> String {
        format!(
            "{:08X?}{:04X?}{:04X?}{:02X?}{:02X?}{:02X?}{:02X?}{:02X?}{:02X?}{:02X?}{:02X?}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

impl core::fmt::Debug for GUID {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:08X?}-{:04X?}-{:04X?}-{:02X?}{:02X?}-{:02X?}{:02X?}{:02X?}{:02X?}{:02X?}{:02X?}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

trait HexReader {
    fn next_u8(&mut self) -> u8;
    fn next_u16(&mut self) -> u16;
    fn next_u32(&mut self) -> u32;
}

impl HexReader for core::str::Bytes<'_> {
    fn next_u8(&mut self) -> u8 {
        let value = self.next().unwrap();
        match value {
            b'0'..=b'9' => value - b'0',
            b'A'..=b'F' => 10 + value - b'A',
            b'a'..=b'f' => 10 + value - b'a',
            _ => panic!(),
        }
    }

    fn next_u16(&mut self) -> u16 {
        self.next_u8().into()
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u8().into()
    }
}
