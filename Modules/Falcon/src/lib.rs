//! Falcon, the signature scheme over NTRU lattices, as liboqs ships it.
//!
//! `Falcon` gives the bytes of the liboqs algorithms `Falcon-512`, `Falcon-1024`,
//! `Falcon-padded-512` and `Falcon-padded-1024`, whose C code is the clean code of PQClean.
//! The C code computes in floating point with an emulation over integers, and this crate
//! ports that emulation bit for bit, so keys and signatures are the same as with the C
//! library for the same random bytes.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "BigInteger.rs"]
mod bigInteger;
#[path = "ChaChaRandom.rs"]
mod chaChaRandom;
#[path = "Encoding.rs"]
mod encoding;
#[path = "Falcon.rs"]
mod falcon;
#[path = "FloatingPoint.rs"]
mod floatingPoint;
#[path = "FourierTransform.rs"]
mod fourierTransform;
#[path = "GaussianSampler.rs"]
mod gaussianSampler;
#[path = "HashToPoint.rs"]
mod hashToPoint;
#[path = "KeyGenerator.rs"]
mod keyGenerator;
#[path = "KeyRefusal.rs"]
mod keyRefusal;
#[path = "ModularPolynomial.rs"]
mod modularPolynomial;
#[path = "NTRUSolver.rs"]
mod ntruSolver;
#[path = "Parameters.rs"]
mod parameters;
#[path = "PrimeModulus.rs"]
mod primeModulus;
#[path = "SecretBasis.rs"]
mod secretBasis;
#[path = "SignatureNorm.rs"]
mod signatureNorm;
#[path = "Signer.rs"]
mod signer;
#[path = "SmallPrime.rs"]
mod smallPrime;
#[path = "SolverFailure.rs"]
mod solverFailure;

pub use falcon::Falcon;
