//! Process allocator instrumentation used by production relay benchmarks.
//!
//! The wrapper delegates storage management to [`std::alloc::System`] and only
//! adds relaxed atomic accounting. It does not change layout, ownership, or
//! failure behavior.

#![allow(unsafe_code)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::atomic::{AtomicU64, Ordering},
};

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static SUPPRESSION_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// A transparent system allocator that records successful allocation calls.
#[derive(Debug, Default)]
pub struct CountingAllocator;

impl CountingAllocator {
    /// Creates an allocation-counting system allocator.
    pub const fn new() -> Self {
        Self
    }
}

// SAFETY: every operation delegates the exact pointer and Layout contract to
// System. Accounting touches only independent atomics and never dereferences
// or changes an allocation pointer.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller provides GlobalAlloc's required valid layout.
        let result = unsafe { System.alloc(layout) };
        record(result, layout.size());
        result
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller provides GlobalAlloc's required valid layout.
        let result = unsafe { System.alloc_zeroed(layout) };
        record(result, layout.size());
        result
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: GlobalAlloc requires the caller to return the original
        // pointer with its matching layout.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: GlobalAlloc requires the original pointer/layout pair and a
        // valid replacement size; System retains the same contract.
        let result = unsafe { System.realloc(pointer, layout, new_size) };
        record(result, new_size);
        result
    }
}

fn record(pointer: *mut u8, bytes: usize) {
    if !pointer.is_null() && !accounting_suppressed() {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

fn accounting_suppressed() -> bool {
    SUPPRESSION_DEPTH.with(|depth| depth.get() != 0)
}

/// Runs synchronous diagnostics bookkeeping without charging allocations made
/// by the observation machinery to the workload being observed.
///
/// The guard is thread-local and must never span an asynchronous suspension.
/// Callers therefore provide an ordinary closure rather than a future.
pub(crate) fn without_counting<T>(operation: impl FnOnce() -> T) -> T {
    struct Restore(u32);

    impl Drop for Restore {
        fn drop(&mut self) {
            SUPPRESSION_DEPTH.with(|depth| depth.set(self.0));
        }
    }

    SUPPRESSION_DEPTH.with(|depth| {
        let previous = depth.get();
        depth.set(previous.saturating_add(1));
        let restore = Restore(previous);
        let result = operation();
        drop(restore);
        result
    })
}

/// Returns successful instrumented allocation calls and requested bytes since
/// start, excluding allocations used solely to serve relay diagnostics.
pub fn snapshot() -> (u64, u64) {
    (
        ALLOCATIONS.load(Ordering::Relaxed),
        ALLOCATED_BYTES.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn wrapper_preserves_system_allocation_contract_and_counts() {
        let _lock = TEST_LOCK.lock().unwrap();
        let allocator = CountingAllocator::new();
        let layout = Layout::from_size_align(128, 16).unwrap();
        let before = snapshot();
        // SAFETY: the test supplies a valid layout and returns the exact
        // pointer/layout pair to the same allocator.
        let pointer = unsafe { allocator.alloc(layout) };
        assert!(!pointer.is_null());
        let after = snapshot();
        assert_eq!(after.0, before.0 + 1);
        assert_eq!(after.1, before.1 + 128);
        // SAFETY: pointer and layout are the pair returned above.
        unsafe { allocator.dealloc(pointer, layout) };
    }

    #[test]
    fn synchronous_observation_allocations_are_excluded_and_nesting_is_restored() {
        let _lock = TEST_LOCK.lock().unwrap();
        let allocator = CountingAllocator::new();
        let layout = Layout::from_size_align(64, 8).unwrap();
        let before = snapshot();
        without_counting(|| {
            without_counting(|| {
                // SAFETY: the test supplies a valid layout and returns the
                // exact pointer/layout pair to the same allocator.
                let pointer = unsafe { allocator.alloc(layout) };
                assert!(!pointer.is_null());
                // SAFETY: pointer and layout are the pair returned above.
                unsafe { allocator.dealloc(pointer, layout) };
            });
        });
        assert_eq!(snapshot(), before);

        // Verify that leaving the outermost guard restores normal accounting.
        // SAFETY: the test supplies a valid layout and returns the exact
        // pointer/layout pair to the same allocator.
        let pointer = unsafe { allocator.alloc(layout) };
        assert!(!pointer.is_null());
        assert_eq!(snapshot(), (before.0 + 1, before.1 + 64));
        // SAFETY: pointer and layout are the pair returned above.
        unsafe { allocator.dealloc(pointer, layout) };
    }
}
