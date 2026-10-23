//! SLH-DSA, the stateless hash-based digital signature scheme of FIPS 205, as liboqs ships it.
//!
//! `SLHDSA` gives the bytes of the 156 liboqs schemes of the family: the pure form
//! `SLH_DSA_PURE_<set>` of each of the twelve parameter sets, and the pre-hash form
//! `SLH_DSA_<function>_PREHASH_<set>` of each set with each of the twelve hash functions of
//! `PreHash`. The C code of liboqs is slh-dsa-c of the PQ Code Package. The port follows its
//! structure: `FORS` signs the digest of the message, and `Hypertree` signs the FORS public
//! key with layers of XMSS trees of WOTS+ keys, all over the hash functions of `HashContext`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "Address.rs"]
mod address;
#[path = "ByteConversion.rs"]
mod byteConversion;
#[path = "FORS.rs"]
mod fors;
#[path = "HashContext.rs"]
mod hashContext;
#[path = "HashFamily.rs"]
mod hashFamily;
#[path = "Hypertree.rs"]
mod hypertree;
#[path = "Parameters.rs"]
mod parameters;
#[path = "PreHash.rs"]
mod preHash;
#[path = "SchemeName.rs"]
mod schemeName;
#[path = "SLHDSA.rs"]
mod slhdsa;

use address::Address;
use byteConversion::ByteConversion;
use fors::FORS;
use hashContext::{HashContext, HashValue};
use hashFamily::HashFamily;
use hypertree::Hypertree;
use parameters::{Parameters, parameterSets};
pub use preHash::PreHash;
use schemeName::SchemeName;
pub use slhdsa::SLHDSA;
