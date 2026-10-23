//! XMSS and XMSS^MT, the stateful hash-based signatures of RFC 8391 and NIST SP 800-208, as
//! liboqs ships them.
//!
//! `XMSS` gives the bytes of the 21 XMSS sets of liboqs and `XMSSMT` the bytes of its 16
//! XMSS^MT sets. Their C code is the XMSS code of liboqs after the reference code of RFC 8391,
//! with the BDS traversal of `xmss_core_fast.c`, whose state lives in the secret key. The secret
//! key of the port is the serialized key of liboqs byte for byte, and each signature advances it
//! as the C code does.
//!
//! One table of parameters, `Parameters`, gives every set from its object identifier, as
//! `params.c` does. `CoreHash` is the hash function of a set, `KeyedHash` the keyed functions of
//! `hash.c`, `WOTS` the one-time signatures, `MerkleTree` the trees and the verification,
//! `BDSState` the traversal state of a tree and `CoreAlgorithms` the key generation and the
//! signatures.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "BDSState.rs"]
mod bdsState;
#[path = "BigEndian.rs"]
mod bigEndian;
#[path = "CoreAlgorithms.rs"]
mod coreAlgorithms;
#[path = "CoreHash.rs"]
mod coreHash;
#[path = "HashAddress.rs"]
mod hashAddress;
#[path = "HashState.rs"]
mod hashState;
#[path = "KeyedHash.rs"]
mod keyedHash;
#[path = "MerkleTree.rs"]
mod merkleTree;
#[path = "Parameters.rs"]
mod parameters;
#[path = "Scheme.rs"]
mod scheme;
#[path = "SigningFailure.rs"]
mod signingFailure;
#[path = "Variant.rs"]
mod variant;
#[path = "WOTS.rs"]
mod wots;
#[path = "XMSS.rs"]
mod xmss;
#[path = "XMSSMT.rs"]
mod xmssmt;

use bdsState::BDSState;
use bigEndian::BigEndian;
use coreAlgorithms::CoreAlgorithms;
use coreHash::CoreHash;
use hashAddress::HashAddress;
use hashState::HashState;
use keyedHash::KeyedHash;
use merkleTree::MerkleTree;
use parameters::Parameters;
use scheme::Scheme;
use signingFailure::SigningFailure;
use variant::Variant;
use wots::WOTS;
pub use xmss::XMSS;
pub use xmssmt::XMSSMT;

#[cfg(test)]
#[path = "TestInputs.rs"]
mod testInputs;
