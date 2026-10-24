//! Test support for the algorithm families.
//!
//! The crate replicates the known-answer programs of liboqs, `tests/kat_kem.c` and
//! `tests/kat_sig.c`, on the capability interfaces, and holds the digests of their output from
//! the liboqs files `tests/KATs/kem/kats.json` and `tests/KATs/sig/kats.json`. A family test
//! runs the program on a Rust algorithm and compares the digest of the text with the digest of
//! the C library. Only tests use the crate.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "KEMKnownAnswerTest.rs"]
mod kemKnownAnswerTest;
#[path = "KnownAnswerDigests.rs"]
mod knownAnswerDigests;
#[path = "KnownAnswerRandom.rs"]
mod knownAnswerRandom;
#[path = "KnownAnswerText.rs"]
mod knownAnswerText;
#[path = "SignatureKnownAnswerTest.rs"]
mod signatureKnownAnswerTest;
#[path = "SignedMessageForm.rs"]
mod signedMessageForm;

pub use kemKnownAnswerTest::KEMKnownAnswerTest;
pub use knownAnswerDigests::KnownAnswerDigests;
pub use knownAnswerRandom::KnownAnswerRandom;
pub use knownAnswerText::KnownAnswerText;
pub use signatureKnownAnswerTest::SignatureKnownAnswerTest;
pub use signedMessageForm::SignedMessageForm;
