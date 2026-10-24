//! Test support for the algorithm families.
//!
//! The crate replicates the test programs of liboqs on the capability interfaces, so that each
//! family runs the same tests. The known-answer programs `tests/kat_kem.c` and
//! `tests/kat_sig.c` come with the digests of their output from the liboqs files
//! `tests/KATs/kem/kats.json` and `tests/KATs/sig/kats.json`. A family test runs a program on
//! a Rust algorithm and compares the digest of the text with the digest of the C library. The
//! correctness, fuzz and memory programs of `tests/test_kem.c`, `tests/fuzz_test_kem.c`,
//! `tests/test_kem_mem.c`, `tests/test_sig.c`, `tests/fuzz_test_sig.c` and
//! `tests/test_sig_mem.c` check the behavior. Only tests use the crate.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "FuzzRandom.rs"]
mod fuzzRandom;
#[path = "JSONValue.rs"]
mod jsonValue;
#[path = "KEMCorrectnessTest.rs"]
mod kemCorrectnessTest;
#[path = "KEMFuzzTest.rs"]
mod kemFuzzTest;
#[path = "KEMKnownAnswerTest.rs"]
mod kemKnownAnswerTest;
#[cfg(feature = "std")]
#[path = "KEMMemoryTest.rs"]
mod kemMemoryTest;
#[path = "KnownAnswerDigests.rs"]
mod knownAnswerDigests;
#[path = "KnownAnswerRandom.rs"]
mod knownAnswerRandom;
#[path = "KnownAnswerText.rs"]
mod knownAnswerText;
#[path = "SignatureCorrectnessTest.rs"]
mod signatureCorrectnessTest;
#[path = "SignatureFuzzTest.rs"]
mod signatureFuzzTest;
#[path = "SignatureKnownAnswerTest.rs"]
mod signatureKnownAnswerTest;
#[cfg(feature = "std")]
#[path = "SignatureMemoryTest.rs"]
mod signatureMemoryTest;
#[path = "SignedMessageForm.rs"]
mod signedMessageForm;
#[cfg(feature = "std")]
#[path = "TestVectorFiles.rs"]
mod testVectorFiles;

pub use fuzzRandom::FuzzRandom;
pub use jsonValue::JSONValue;
pub use kemCorrectnessTest::KEMCorrectnessTest;
pub use kemFuzzTest::KEMFuzzTest;
pub use kemKnownAnswerTest::KEMKnownAnswerTest;
#[cfg(feature = "std")]
pub use kemMemoryTest::KEMMemoryTest;
pub use knownAnswerDigests::KnownAnswerDigests;
pub use knownAnswerRandom::KnownAnswerRandom;
pub use knownAnswerText::KnownAnswerText;
pub use signatureCorrectnessTest::SignatureCorrectnessTest;
pub use signatureFuzzTest::SignatureFuzzTest;
pub use signatureKnownAnswerTest::SignatureKnownAnswerTest;
#[cfg(feature = "std")]
pub use signatureMemoryTest::SignatureMemoryTest;
pub use signedMessageForm::SignedMessageForm;
#[cfg(feature = "std")]
pub use testVectorFiles::TestVectorFiles;
