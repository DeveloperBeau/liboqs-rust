//! BIKE, the bit flipping key encapsulation of round 4 of the NIST process, as liboqs ships it.
//!
//! `BIKE` gives the bytes of the liboqs algorithms `BIKE-L1`, `BIKE-L3` and `BIKE-L5`, whose C
//! code is the additional implementation of the BIKE team, in its portable form. The code is a
//! quasi-cyclic moderate-density parity-check code over the ring `GF(2)[x] / (x^r - 1)` of
//! `PolynomialRing`. `Sampler` draws the secret blocks and the error vectors from the SHAKE256
//! function of `PseudorandomFunction`, and `Decoder` is the Black-Gray-Flip decoder of the C
//! code, with the bit-sliced counters of `ParityCheckCounters` over the rotations of a
//! `Syndrome`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "BIKE.rs"]
mod bike;
#[path = "Decoder.rs"]
mod decoder;
#[path = "Parameters.rs"]
mod parameters;
#[path = "ParityCheckCounters.rs"]
mod parityCheckCounters;
#[path = "PolynomialRing.rs"]
mod polynomialRing;
#[path = "PseudorandomFunction.rs"]
mod pseudorandomFunction;
#[path = "Sampler.rs"]
mod sampler;
#[path = "Syndrome.rs"]
mod syndrome;

pub use bike::BIKE;
use parameters::Parameters;

#[cfg(test)]
#[path = "TestSupport.rs"]
mod testSupport;
