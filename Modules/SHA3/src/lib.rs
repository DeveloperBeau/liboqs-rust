//! SHA-3 hash functions and the SHAKE extendable-output functions (FIPS 202).
//!
//! The types follow the incremental API of liboqs `src/common/sha3`. A hash absorbs input in
//! any number of calls and then gives its digest. A SHAKE function absorbs input, finalizes,
//! and then gives a stream of output bytes that `SHAKEReader` squeezes in any number of calls.
//! The output stream is the same however the calls split it, as with liboqs
//! `OQS_SHA3_shake128_inc_squeeze`.

#![cfg_attr(not(feature = "std"), no_std)]

#[path = "KeccakF1600.rs"]
mod keccakF1600;
#[path = "KeccakSponge.rs"]
mod keccakSponge;
#[path = "SHA3224.rs"]
mod sha3224;
#[path = "SHA3256.rs"]
mod sha3256;
#[path = "SHA3384.rs"]
mod sha3384;
#[path = "SHA3512.rs"]
mod sha3512;
#[path = "SHAKE128.rs"]
mod shake128;
#[path = "SHAKE256.rs"]
mod shake256;
#[path = "SHAKEReader.rs"]
mod shakeReader;

pub use keccakF1600::KeccakF1600;
use keccakSponge::KeccakSponge;
pub use sha3224::SHA3224;
pub use sha3256::SHA3256;
pub use sha3384::SHA3384;
pub use sha3512::SHA3512;
pub use shake128::SHAKE128;
pub use shake256::SHAKE256;
pub use shakeReader::SHAKEReader;
