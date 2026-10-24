//! Plain data types of the native liboqs port.
//!
//! The types describe algorithms and hold keys, ciphertexts and shared secrets. They have no
//! behavior beyond what the data is. `SecretBytes` wipes its bytes when it is dropped.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "Encapsulation.rs"]
mod encapsulation;
#[path = "KEMDescription.rs"]
mod kemDescription;
#[path = "KeyPair.rs"]
mod keyPair;
#[path = "OQSError.rs"]
mod oqsError;
#[path = "SecretBytes.rs"]
mod secretBytes;
#[path = "SignatureDescription.rs"]
mod signatureDescription;
#[path = "StatefulSignatureDescription.rs"]
mod statefulSignatureDescription;

pub use encapsulation::Encapsulation;
pub use kemDescription::KEMDescription;
pub use keyPair::KeyPair;
pub use oqsError::OQSError;
pub use secretBytes::SecretBytes;
pub use signatureDescription::SignatureDescription;
pub use statefulSignatureDescription::StatefulSignatureDescription;
