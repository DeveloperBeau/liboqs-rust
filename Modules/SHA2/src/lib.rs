//! SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256 (FIPS 180-4).
//!
//! The types follow the incremental API of liboqs `src/common/sha2`: a hash absorbs input in
//! any number of calls, a clone keeps a hash state for reuse, and `finalize` gives the digest.
//! The SHA-2 API of liboqs has only SHA-256, SHA-384 and SHA-512, and the other three follow
//! the same API.

#![cfg_attr(not(feature = "std"), no_std)]

#[path = "SHA224.rs"]
mod sha224;
#[path = "SHA256.rs"]
mod sha256;
#[path = "SHA384.rs"]
mod sha384;
#[path = "SHA512.rs"]
mod sha512;
#[path = "SHA512224.rs"]
mod sha512224;
#[path = "SHA512256.rs"]
mod sha512256;
#[path = "SHA512Core.rs"]
mod sha512Core;

pub use sha224::SHA224;
pub use sha256::SHA256;
pub use sha384::SHA384;
pub use sha512::SHA512;
use sha512Core::SHA512Core;
pub use sha512224::SHA512224;
pub use sha512256::SHA512256;
