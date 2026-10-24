use alloc::vec::Vec;
use core::fmt;

/// Bytes of secret material, such as a secret key or a shared secret, that are wiped when they
/// are dropped.
///
/// The type has no equality operator, because a plain comparison of secret bytes leaks their
/// value through its run time. Compare `bytes()` in tests only.
#[derive(Clone)]
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    /// Makes secret bytes that own a vector of bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes { bytes }
    }

    /// Makes secret bytes of a length, with each byte zero.
    pub fn zeroed(length: usize) -> Self {
        SecretBytes {
            bytes: alloc::vec![0; length],
        }
    }

    /// The secret bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The secret bytes, for an algorithm that writes them.
    pub fn mutableBytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SecretBytes({} bytes)", self.bytes.len())
    }
}

/// Writes zero over each byte in a way that the compiler cannot remove as a dead store.
///
/// This is the one `unsafe` function of the shipped crates. `write_volatile` needs `unsafe`,
/// and a plain write before a drop is a dead store that the optimizer may delete.
#[allow(unsafe_code)]
fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, aligned and exclusive reference to one initialized byte.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::{SecretBytes, wipe};
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicU8, Ordering};

    /// A block size that no other test of this crate allocates, so the allocator can tell the
    /// block of the drop test from every other block.
    const markedSize: usize = 6271;
    const notSeen: u8 = 0;
    const freedAsZero: u8 = 1;
    const freedWithData: u8 = 2;
    static lastMarkedFree: AtomicU8 = AtomicU8::new(notSeen);

    /// The system allocator, which records whether a freed block of the marked size held only
    /// zero bytes. It proves the wipe of `Drop` without a read of freed memory.
    struct RecordingAllocator;

    #[allow(unsafe_code)]
    // SAFETY: each method forwards to the system allocator with the same arguments.
    unsafe impl GlobalAlloc for RecordingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller keeps the contract of `GlobalAlloc::alloc`.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            if layout.size() == markedSize {
                // SAFETY: the block is still allocated and holds `layout.size()` bytes.
                let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
                let outcome = if bytes.iter().all(|byte| *byte == 0) {
                    freedAsZero
                } else {
                    freedWithData
                };
                lastMarkedFree.store(outcome, Ordering::SeqCst);
            }
            // SAFETY: the caller keeps the contract of `GlobalAlloc::dealloc`.
            unsafe { System.dealloc(pointer, layout) }
        }
    }

    #[global_allocator]
    static allocator: RecordingAllocator = RecordingAllocator;

    #[test]
    fn dropWipesTheBytesBeforeTheMemoryIsFreed() {
        lastMarkedFree.store(notSeen, Ordering::SeqCst);
        drop(SecretBytes::new(vec![0xA5; markedSize]));
        assert_eq!(lastMarkedFree.load(Ordering::SeqCst), freedAsZero);
        // The control: a plain vector of the same size is freed with its bytes intact, so the
        // allocator would see a missing wipe.
        drop(vec![0xA5u8; markedSize]);
        assert_eq!(lastMarkedFree.load(Ordering::SeqCst), freedWithData);
    }

    #[test]
    fn wipeWritesZeroOverEveryByte() {
        let mut bytes = [0xA5u8; 37];
        wipe(&mut bytes);
        assert_eq!(bytes, [0u8; 37]);
    }

    #[test]
    fn newKeepsTheBytesAndZeroedMakesZeroBytes() {
        let secret = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(secret.bytes(), &[1, 2, 3]);
        assert_eq!(SecretBytes::zeroed(4).bytes(), &[0, 0, 0, 0]);
        assert!(SecretBytes::zeroed(0).bytes().is_empty());
    }

    #[test]
    fn mutableBytesWriteThroughToTheBytes() {
        let mut secret = SecretBytes::zeroed(3);
        secret.mutableBytes()[1] = 9;
        assert_eq!(secret.bytes(), &[0, 9, 0]);
    }

    #[test]
    fn debugTextShowsTheLengthButNeverTheBytes() {
        let secret = SecretBytes::new(vec![0xDE, 0xAD]);
        assert_eq!(format!("{secret:?}"), "SecretBytes(2 bytes)");
    }

    #[test]
    fn cloneIsAnIndependentCopy() {
        let original = SecretBytes::new(vec![7, 7]);
        let mut copy = original.clone();
        copy.mutableBytes()[0] = 1;
        assert_eq!(original.bytes(), &[7, 7]);
        assert_eq!(copy.bytes(), &[1, 7]);
    }
}
