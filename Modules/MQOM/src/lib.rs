//! MQOM, the MQ on my Mind signature scheme, as liboqs ships it.
//!
//! `MQOM` gives the bytes of the twelve liboqs algorithms
//! `mqom2_cat<level>_gf16_<trade off>_r<rounds>`, whose C code is the default implementation of
//! the MQOM team. A signature proves the knowledge of a solution x over GF(16) of a system of
//! quadratic equations, the secret key, without showing it. The seed trees of `GGMTree`, the
//! line commitments of `LineCommitment` and the polynomial proof of `PIOP` follow that C code
//! step by step, so every intermediate value, and so every signature, is the one of the C
//! library. The seeds are encrypted with AES-128 or Rijndael-256 in `SeedCipher`, and every
//! hash is SHAKE.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "BitPlanes.rs"]
mod bitPlanes;
#[path = "EquationSystem.rs"]
mod equationSystem;
#[path = "ExtensionField.rs"]
mod extensionField;
#[path = "GGMTree.rs"]
mod ggmTree;
#[path = "InternalAlgorithms.rs"]
mod internalAlgorithms;
#[path = "LineCommitment.rs"]
mod lineCommitment;
#[path = "LineTerms.rs"]
mod lineTerms;
#[path = "MQOM.rs"]
mod mqom;
#[path = "Parameters.rs"]
mod parameters;
#[path = "PIOP.rs"]
mod piop;
#[path = "PseudorandomGenerator.rs"]
mod pseudorandomGenerator;
#[path = "SeedCipher.rs"]
mod seedCipher;
#[cfg(test)]
#[path = "TestInputs.rs"]
mod testInputs;
#[path = "XOF.rs"]
mod xof;

use bitPlanes::BitPlanes;
use equationSystem::EquationSystem;
use extensionField::ExtensionField;
use ggmTree::GGMTree;
use lineCommitment::LineCommitment;
use lineTerms::LineTerms;
pub use mqom::MQOM;
use parameters::Parameters;
use piop::PIOP;
use pseudorandomGenerator::PseudorandomGenerator;
use seedCipher::SeedCipher;
use xof::XOF;
