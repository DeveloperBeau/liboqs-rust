//! A native Rust port of liboqs, the Open Quantum Safe library.
//!
//! The crate is the composition root of the port. `Registry` finds each algorithm by its liboqs
//! name, and the crate re-exports the families, the capability interfaces and the data types,
//! so a user needs only this crate. Each operation takes its random source as an argument.
//! `SystemRandom` is the random source of the operating system.

#![cfg_attr(not(feature = "std"), no_std)]

#[path = "Registry.rs"]
mod registry;

pub use OQSNativeDomain::{
    KeyEncapsulating, KeyStatePersisting, RandomGenerating, Signing, StatefulSigning,
};
pub use OQSNativeEntities::{
    Encapsulation, KEMDescription, KeyPair, OQSError, SecretBytes, SignatureDescription,
    StatefulSignatureDescription,
};
pub use OQSNativeMLKEM::{Kyber, MLKEM};
#[cfg(feature = "std")]
pub use OQSNativeSystemRandom::SystemRandom;
pub use registry::Registry;
