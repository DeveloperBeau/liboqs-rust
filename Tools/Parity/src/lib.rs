//! Parity of every Rust algorithm with the C algorithm of the same name.
//!
//! `KEMParity` and `SignatureParity` run the base case of the Swift and Zig ports and seeded
//! variations, and compare each value of the Rust side with the value of the C side.
//! `StatefulParity` runs the base case and the signatures of one key of a stateful scheme.
//! `Snapshot` is the snapshot format of the Swift and Zig ports. `ParityJob` runs the checks of
//! many algorithms on every processor. The tests of the crate run every registered algorithm, and
//! the `parity` program runs the full gate.

#[path = "KEMParity.rs"]
mod kemParity;
#[path = "LargeStack.rs"]
mod largeStack;
#[path = "ParityJob.rs"]
mod parityJob;
#[path = "ParityMismatch.rs"]
mod parityMismatch;
#[path = "ParityOptions.rs"]
mod parityOptions;
#[path = "ParitySettings.rs"]
mod paritySettings;
#[path = "SignatureParity.rs"]
mod signatureParity;
#[path = "Snapshot.rs"]
mod snapshot;
#[path = "StatefulParity.rs"]
mod statefulParity;
#[path = "VariationGenerator.rs"]
mod variationGenerator;

pub use kemParity::{KEMBaseCase, KEMParity};
pub use largeStack::LargeStack;
pub use parityJob::ParityJob;
pub use parityMismatch::ParityMismatch;
pub use parityOptions::ParityOptions;
pub use paritySettings::ParitySettings;
pub use signatureParity::{SignatureBaseCase, SignatureParity, baseCaseMessage};
pub use snapshot::Snapshot;
pub use statefulParity::StatefulParity;
pub use variationGenerator::VariationGenerator;
