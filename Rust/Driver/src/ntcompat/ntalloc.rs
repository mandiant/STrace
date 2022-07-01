// allocator for stdlib things
use super::nt;
use core::alloc::{GlobalAlloc, Layout};

pub struct KernelAlloc;
pub const NON_PAGED_POOL_NX: u32 = 512;
unsafe impl GlobalAlloc for KernelAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            panic!("Zero sized allocations are insidious, and you have one");
        }

        let pool = nt::ExAllocatePool(NON_PAGED_POOL_NX, layout.size() as _);

        if pool.is_null() {
            panic!("[kernel-alloc] failed to allocate pool.");
        }

        pool as _
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) { nt::ExFreePool(ptr as _); }
}

// set "rust-analyzer.allTargets": false in rust-analyzer preferences to
// suppress weird warning
#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    panic!("{:?} alloc memory error", layout);
}

#[global_allocator]
static GLOBAL: KernelAlloc = KernelAlloc;
