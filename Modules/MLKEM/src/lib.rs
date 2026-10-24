//! ML-KEM, the module-lattice key encapsulation mechanism of FIPS 203, and Kyber, its
//! predecessor of round 3, as liboqs ships them.
//!
//! `MLKEM` follows FIPS 203 and gives the bytes of the liboqs algorithms `ML-KEM-512`,
//! `ML-KEM-768` and `ML-KEM-1024`, whose C code is mlkem-native. `Kyber` gives the bytes of
//! `Kyber512`, `Kyber768` and `Kyber1024`, whose C code is the reference code of the Kyber team.
//! Both share the lattice arithmetic of `Polynomial` and the scheme of `PublicKeyEncryption`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "Kyber.rs"]
mod kyber;
#[path = "MLKEM.rs"]
mod mlkem;
#[path = "Parameters.rs"]
mod parameters;
#[path = "Polynomial.rs"]
mod polynomial;
#[path = "PublicKeyEncryption.rs"]
mod publicKeyEncryption;

pub use kyber::Kyber;
pub use mlkem::MLKEM;
use parameters::Parameters;
