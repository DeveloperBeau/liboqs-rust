//! LMS and HSS, the hash-based stateful signatures of RFC 8554, as liboqs ships them.
//!
//! `LMS` gives the bytes of the 33 liboqs algorithms from `LMS_SHA256_H5_W1` to
//! `LMS_SHA256_H20_W8_H20_W8`, whose C code is the hash-sigs code of Cisco with the seed
//! method of ACVP. A set of one level is one LMS tree, and a set of two levels is an HSS key.
//! `LMSWorkingKey` is the working key of hash-sigs: a secret key loaded once that signs many
//! messages without a new load.
//!
//! The one-time signatures of `OneTimeSignature`, the trees of `MerkleTree` and the
//! verification of `SignatureVerification` follow the C code step by step, so every signature,
//! every key and every verdict is the one of the C library.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "AuxiliaryData.rs"]
mod auxiliaryData;
#[path = "LevelType.rs"]
mod levelType;
#[path = "LMS.rs"]
mod lms;
#[path = "LMSWorkingKey.rs"]
mod lmsWorkingKey;
#[path = "MerkleTree.rs"]
mod merkleTree;
#[path = "OneTimeSignature.rs"]
mod oneTimeSignature;
#[path = "OneTimeSignatureType.rs"]
mod oneTimeSignatureType;
#[path = "ParameterSet.rs"]
mod parameterSet;
#[path = "Parameters.rs"]
mod parameters;
#[path = "PrivateKey.rs"]
mod privateKey;
#[path = "SeedDerivation.rs"]
mod seedDerivation;
#[path = "SignatureVerification.rs"]
mod signatureVerification;
#[path = "TreeBuilder.rs"]
mod treeBuilder;
#[path = "TreeState.rs"]
mod treeState;
#[path = "TreeType.rs"]
mod treeType;

use auxiliaryData::AuxiliaryData;
use levelType::LevelType;
pub use lms::LMS;
pub use lmsWorkingKey::LMSWorkingKey;
use merkleTree::MerkleTree;
use oneTimeSignature::OneTimeSignature;
use oneTimeSignatureType::OneTimeSignatureType;
use parameterSet::ParameterSet;
use privateKey::PrivateKey;
use seedDerivation::SeedDerivation;
use signatureVerification::SignatureVerification;
use treeBuilder::TreeBuilder;
use treeState::TreeState;
use treeType::TreeType;
