//! UOV, the Unbalanced Oil and Vinegar signature scheme, as liboqs ships it.
//!
//! `UOV` gives the bytes of the twelve liboqs algorithms from `OV-Is` to `OV-V-pkc-skc`,
//! whose C code is the reference code of the pqov project. The arithmetic of GF(16) and
//! GF(256) is exact, and the public map, the key pair and the signature compute the same sums
//! as the C code, so every key and every signature is the one of the C library for the same
//! random bytes.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "BatchedMatrix.rs"]
mod batchedMatrix;
#[path = "Field.rs"]
mod field;
#[path = "FieldArithmetic.rs"]
mod fieldArithmetic;
#[path = "GeneratorPowers.rs"]
mod generatorPowers;
#[path = "GF16.rs"]
mod gf16;
#[path = "GF256.rs"]
mod gf256;
#[path = "KeyForm.rs"]
mod keyForm;
#[path = "KeyGenerator.rs"]
mod keyGenerator;
#[path = "LinearSystem.rs"]
mod linearSystem;
#[path = "OilMatrix.rs"]
mod oilMatrix;
#[path = "PaddedEntries.rs"]
mod paddedEntries;
#[path = "Parameters.rs"]
mod parameters;
#[path = "PublicMap.rs"]
mod publicMap;
#[path = "SaltedMessage.rs"]
mod saltedMessage;
#[path = "Signer.rs"]
mod signer;
#[cfg(test)]
#[path = "TestInputs.rs"]
mod testInputs;
#[path = "UOV.rs"]
mod uov;

use batchedMatrix::BatchedMatrix;
use field::Field;
use fieldArithmetic::FieldArithmetic;
use generatorPowers::GeneratorPowers;
use keyForm::KeyForm;
use keyGenerator::KeyGenerator;
use linearSystem::LinearSystem;
use oilMatrix::OilMatrix;
use paddedEntries::PaddedEntries;
use publicMap::PublicMap;
use saltedMessage::SaltedMessage;
use signer::Signer;
pub use uov::UOV;
