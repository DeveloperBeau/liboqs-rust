//! The liboqs C library as a test oracle.
//!
//! The crate links the C library that `cargo xtask fetch-oracle` builds at the version in
//! `LIBOQS_VERSION`. The parity tests compare each Rust algorithm with the C algorithm of the
//! same name through this crate. No shipped crate depends on it.
//!
//! `COracle` holds the lock of the C library for the time of its use, because the C library
//! has one global random source. `OracleMechanism` and `OracleSignatureScheme` give the C
//! algorithms the capability interfaces of the Rust algorithms, so a test can run the parity
//! harness against the C code itself.
//!
//! Without the `std` feature the crate is empty, because the oracle is a test tool of a hosted
//! build.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
#[path = "COracle.rs"]
mod cOracle;
#[cfg(feature = "std")]
#[path = "OracleMechanism.rs"]
mod oracleMechanism;
#[cfg(feature = "std")]
#[path = "OracleRandomness.rs"]
mod oracleRandomness;
#[cfg(feature = "std")]
#[path = "OracleSignatureScheme.rs"]
mod oracleSignatureScheme;

#[cfg(feature = "std")]
pub use cOracle::COracle;
#[cfg(feature = "std")]
pub use oracleMechanism::OracleMechanism;
#[cfg(feature = "std")]
pub use oracleRandomness::OracleRandomness;
#[cfg(feature = "std")]
pub use oracleSignatureScheme::OracleSignatureScheme;
