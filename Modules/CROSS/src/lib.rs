//! CROSS, the Codes and Restricted Objects Signature Scheme, as liboqs ships it.
//!
//! `CROSS` gives the bytes of the eighteen liboqs algorithms from `cross-rsdp-128-balanced` to
//! `cross-rsdpg-256-small`, whose C code is the clean code of the CROSS team in
//! `src/sig/cross`. A signature proves the knowledge of a restricted error vector of a public
//! syndrome over many rounds, and SHAKE makes the proof non-interactive. The port follows the C
//! code step by step: the reductions with a second form of zero, the samplers that draw a fixed
//! number of random bits, the seed tree and the Merkle tree of the shape of each set, and the
//! checks of the padding bits of the keys and the signatures.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "BitReader.rs"]
mod bitReader;
#[path = "CodeParameters.rs"]
mod codeParameters;
#[path = "CROSS.rs"]
mod cross;
#[path = "FieldArithmetic.rs"]
mod fieldArithmetic;
#[path = "HashFunction.rs"]
mod hashFunction;
#[path = "KeyMaterial.rs"]
mod keyMaterial;
#[path = "MerkleTree.rs"]
mod merkleTree;
#[path = "Packing.rs"]
mod packing;
#[path = "Parameters.rs"]
mod parameters;
#[path = "Problem.rs"]
mod problem;
#[path = "PublicMatrices.rs"]
mod publicMatrices;
#[path = "RestrictedArithmetic.rs"]
mod restrictedArithmetic;
#[path = "Sampler.rs"]
mod sampler;
#[path = "SeedTree.rs"]
mod seedTree;
#[path = "Signer.rs"]
mod signer;
#[cfg(test)]
#[path = "TestInputs.rs"]
mod testInputs;
#[path = "Tradeoff.rs"]
mod tradeoff;
#[path = "TreeLayout.rs"]
mod treeLayout;
#[path = "Verifier.rs"]
mod verifier;

use bitReader::BitReader;
use codeParameters::CodeParameters;
pub use cross::CROSS;
use fieldArithmetic::FieldArithmetic;
use hashFunction::HashFunction;
use keyMaterial::KeyMaterial;
use merkleTree::MerkleTree;
use packing::Packing;
use parameters::Parameters;
use problem::Problem;
use publicMatrices::PublicMatrices;
use restrictedArithmetic::RestrictedArithmetic;
use sampler::Sampler;
use seedTree::SeedTree;
use signer::Signer;
use tradeoff::Tradeoff;
use treeLayout::TreeLayout;
use verifier::Verifier;
