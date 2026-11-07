//! Capability interfaces of the native liboqs port, and the rules that use them.
//!
//! Each algorithm family implements one of `KeyEncapsulating`, `Signing` and `StatefulSigning`
//! for each parameter set. An algorithm draws its random bytes from a `RandomGenerating` source
//! that the caller passes in, so tests can give it a seeded source and no algorithm reaches the
//! operating system directly.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "InputLength.rs"]
mod inputLength;
#[path = "KeyEncapsulating.rs"]
mod keyEncapsulating;
#[path = "KeyStatePersisting.rs"]
mod keyStatePersisting;
#[path = "RandomGenerating.rs"]
mod randomGenerating;
#[path = "Signing.rs"]
mod signing;
#[path = "StatefulSigning.rs"]
mod statefulSigning;

pub use inputLength::InputLength;
pub use keyEncapsulating::KeyEncapsulating;
pub use keyStatePersisting::KeyStatePersisting;
pub use randomGenerating::RandomGenerating;
pub use signing::Signing;
pub use statefulSigning::StatefulSigning;

#[cfg(test)]
#[path = "TestDoubles.rs"]
mod testDoubles;
