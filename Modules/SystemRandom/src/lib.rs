//! Random bytes from the operating system, for the native liboqs port.
//!
//! This is the only crate that reaches the random source of the operating system. Every
//! algorithm takes its random source as an argument, so the composition root passes a
//! `SystemRandom` to production code and a seeded generator to tests.
//!
//! The source is `/dev/urandom`, so the crate works on Unix systems. The owner chose Unix
//! only for now. Another system needs its own adapter.

#[path = "SystemRandom.rs"]
mod systemRandom;

pub use systemRandom::SystemRandom;
