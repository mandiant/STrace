pub struct MachineState<'a> {
    pub paramCount: u32,
    pub pStackArgs: &'a [u64],
    pub pRegArgs: &'a [u64],
}

impl MachineState<'_> {
    pub fn new(paramCount: u32, regArgSize: u32, pStack: *const u64, pRegs: *const u64) -> Self {
        let pStackArgs;
        let pRegArgs;
        unsafe {
            pStackArgs = core::slice::from_raw_parts(pStack, (paramCount - regArgSize) as usize);
            pRegArgs = core::slice::from_raw_parts(pRegs, regArgSize as usize);
        };

        Self {
            paramCount,
            pStackArgs,
            pRegArgs,
        }
    }

    pub fn read_arg(&self, idx: u8) -> Option<u64> {
        if idx as u32 > self.paramCount {
            return None;
        }

        if idx as usize >= self.pRegArgs.len() {
            return Some(self.pStackArgs[idx as usize - self.pRegArgs.len()]);
        } else {
            return Some(self.pRegArgs[idx as usize]);
        }
    }
}
