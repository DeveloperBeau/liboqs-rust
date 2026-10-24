//! NTRU, the lattice key encapsulation mechanism of round 3 of the NIST process, as liboqs
//! ships it.
//!
//! `NTRU` gives the bytes of the liboqs algorithms `NTRU-HPS-2048-509`, `NTRU-HPS-2048-677`,
//! `NTRU-HPS-4096-821`, `NTRU-HPS-4096-1229`, `NTRU-HRSS-701` and `NTRU-HRSS-1373`, whose C
//! code is the clean code of PQClean, from the reference code of the NTRU team. The scheme
//! works in the ring `Z[x] / (x^n - 1)` with a prime `n`, modulo 3 and modulo a power of two
//! `q`. `PublicKeyEncryption` is the deterministic encryption of `owcpa.c`, on the arithmetic
//! of `PolynomialRing`, `PolynomialMultiplication` and `PolynomialInversion`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "MultiplicationMethod.rs"]
mod multiplicationMethod;
#[path = "NTRU.rs"]
mod ntru;
#[path = "Packing.rs"]
mod packing;
#[path = "Parameters.rs"]
mod parameters;
#[path = "PolynomialInversion.rs"]
mod polynomialInversion;
#[path = "PolynomialMultiplication.rs"]
mod polynomialMultiplication;
#[path = "PolynomialRing.rs"]
mod polynomialRing;
#[path = "PublicKeyEncryption.rs"]
mod publicKeyEncryption;
#[path = "Sampler.rs"]
mod sampler;
#[path = "Variant.rs"]
mod variant;

use multiplicationMethod::MultiplicationMethod;
pub use ntru::NTRU;
use packing::Packing;
use parameters::Parameters;
use polynomialInversion::PolynomialInversion;
use polynomialMultiplication::PolynomialMultiplication;
use polynomialRing::PolynomialRing;
use publicKeyEncryption::PublicKeyEncryption;
use sampler::Sampler;
use variant::Variant;

#[cfg(test)]
#[path = "TestInputs.rs"]
mod testInputs;
